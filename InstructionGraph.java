package com.wuaipojie;

import capstone.api.Instruction;
import guru.nidi.graphviz.attribute.*;
import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;
import guru.nidi.graphviz.model.Factory;
import guru.nidi.graphviz.model.MutableGraph;
import guru.nidi.graphviz.model.MutableNode;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class InstructionGraph {
    private Set<Instruction> nodes = new HashSet<>();
    private Set<List<Instruction>> mergedNodes = new HashSet<>();
    private Set<List<Instruction>> controlNodes = new HashSet<>();
    private Set<List<Instruction>> realNodes = new HashSet<>();
    private Map<Long, List<Instruction>> toMap = new HashMap<>();
    private Map<Long, List<Instruction>> fromMap = new HashMap<>();
    private Map<Long, List<Instruction>> realFromMap = new HashMap<>();
    private long moduleBase = 0;

    private MutableGraph graph = Factory.mutGraph("example1").setDirected(true)
            .graphAttrs().add(Rank.dir(Rank.RankDir.TOP_TO_BOTTOM))
            .nodeAttrs().add(Font.name("monospace"));
    // 区块的最后一个地址对应的node
    private Map<Long, MutableNode> graphNodeMap = new HashMap<>();

    private Instruction entry = null;
    private List<Instruction> preDispather = null;
    private String reg = null;

    private Map<Long, Integer> commonBlock = new HashMap<>();
    private Map<Long, Set<Long>> blockAreaStart = new HashMap<>();
    // 这里现在修改为只保存 csel 的 key ins  （因为keyIns可能在common block中，所以start to keyins）
    private Map<Long, Long> startMapTokeyIns = new HashMap<>();

    private Map<Long, List<Instruction>> flowBlockAreaMap = new HashMap<>();
    private Map<Long, List<Instruction>> condBlockAreaMap = new HashMap<>();

    HashMap<Long, String> patchBrInfo = new HashMap<>();

    private Set<Long> manualControlNodes = new HashSet<>();

    public void setModuleBase(long moduleBase) {
        this.moduleBase = moduleBase;
    }

    public boolean isKeyIns(long address) {
        return startMapTokeyIns.containsValue(address);
    }

    public void addLink(Instruction ins, Instruction to) {
        addNode(ins);
        addNode(to);
        putLinkToMap(toMap, ins.getAddress(), to);
        putLinkToMap(fromMap, to.getAddress(), ins);
    }

    public void setBrInfo(long offset, long branchAddr) {
        patchBrInfo.put(offset, String.format("bl %d", branchAddr));
    }

    public void setManualControlNodes(long[] nodeStartList) {
        for (long offset : nodeStartList)
            manualControlNodes.add(offset);
    }

    public boolean isBlockAreaStartOrEntry(long address) {
        // 第一遍explorer的时候，blockAreaStart是空的，必然返回false
        // 就不会 addBlockAreaLink
        return blockAreaStart.containsKey(address);
//        for (long start : blockAreaStart.keySet())
//            if (ins.getAddress() == address)
//                return true;
//        return false;
    }

    public void addBlockAreaLink(Instruction ins, Instruction to, boolean cond) {
        // TODO: 这里是为了筛除内部循环，但也可能是在控制流平坦化控制下的循环（如果发现 link 的有问题，有缺失，可以处理）
        if (ins.getAddress() == to.getAddress()) {
            System.out.printf("flow block area link error, link self %x -> %x\n", ins.getAddress(), to.getAddress());
            return;
        }
        if (startMapTokeyIns.containsKey(ins.getAddress())) {
            // 从 putLinkToMap 复制上来的，cond的这个有点不一样
            long fromAddress = ins.getAddress();
            if (!condBlockAreaMap.containsKey(fromAddress)) {
                List<Instruction> tmp = new ArrayList<>(2);
                tmp.add(null);
                tmp.add(null);
                condBlockAreaMap.put(fromAddress, tmp);
            }

//            boolean include = false;
//            for (Instruction i : condBlockAreaMap.get(fromAddress))
//                // 由于 condBlockAreaMap 会提前填null，所以就需要进行判空
//                if (i != null && i.getAddress() == to.getAddress()) {
//                    include = true;
//                    break;
//                }
//            if (!include)
            condBlockAreaMap.get(fromAddress).set(cond ? 1 : 0, to);
        } else {
//            if (flowBlockAreaMap.containsKey(ins.getAddress()) && flowBlockAreaMap.get(ins.getAddress()).get(0).getAddress() != to.getAddress())
//                System.out.printf("flow block area link error, flow multi link %x -> %x\n", ins.getAddress(), to.getAddress());
//            if (ins.getAddress() == to.getAddress())
//                System.out.printf("flow block area link error, link self %x -> %x\n", ins.getAddress(), to.getAddress());
//            System.out.printf("flow block area link, %x -> %x\n", ins.getAddress(), to.getAddress());
//            if (ins.getAddress() != to.getAddress())
            putLinkToMap(flowBlockAreaMap, ins.getAddress(), to);
        }
    }

    public void addRealLink(Instruction ins, Instruction to) {
        // 只有 block area 的 link 才增加
        // 所以 to 是 block area start，并且 ins 不能在 to 所在的 block area 中（除非是在commonBlock）
//        if (blockAreaStart.containsKey(to.getAddress())
//                && (!blockAreaStart.get(to.getAddress()).contains(ins.getAddress())
//                    || commonBlock.containsKey(getMergeNodeByEnd(ins.getAddress()).get(0).getAddress())))

        // 更进一步，直接让 ins 只记录 block area start 之间的东西；
        putLinkToMap(realFromMap, to.getAddress(), ins);
    }

    public Set<Instruction> getNodes() {
        return nodes;
    }

    public boolean isInRealBlock(long address) {
        // 由于第一次 explorer 的时候，会有一些短缺，所以判断不是controlNodes是更稳妥的做法
        for (List<Instruction> block : controlNodes)
            for (Instruction ins : block)
                if (ins.getAddress() == address)
                    return false;
        return true;
    }

    public boolean isPreDispatcher(long address) {
        if (this.preDispather == null)
            return false;
        return address == this.preDispather.get(0).getAddress();
    }

    public boolean isCommonBlockIns(long address) {
        for (long key : commonBlock.keySet()) {
            if (commonBlock.get(key) <= 1)
                continue;
            List<Instruction> block = getMergeNodeByStart(key);
            for (Instruction ins : block)
                if (ins.getAddress() == address)
                    return true;
        }
        return false;
    }

    public void findEntry() {
        for (Instruction i : nodes) {
            if (i.getAddress() == 0x2a5c8 + moduleBase) {
                System.out.println(fromMap.get(i.getAddress()));
            }
            if (!fromMap.containsKey(i.getAddress())) {
                entry = i;
            }
        }
        if (entry == null) {
            throw new RuntimeException("entry is null");
        }
    }

    public void mergeNodes(boolean prepareImage) {
        Set<Long> accessed = new HashSet<>();
        Stack<Instruction> pending = new Stack<>();
        // 前一个区块的最后一个地址对应的node，相当于包含了link的信息
        List<Link> graphLinkMap = new ArrayList<>();
        pending.push(entry);
        accessed.add(entry.getAddress());
        while (!pending.empty()) {
            Instruction ins = pending.pop();
            List<Instruction> from = fromMap.get(ins.getAddress());
            StringBuilder sb = new StringBuilder(String.format("<tr><td align='left'>%X  %s</td></tr>", ins.getAddress() - moduleBase, ins));

            List<Instruction> mergedNode = new ArrayList<>();
            mergedNode.add(ins);
            while (canMerge(ins)) {
                ins = toMap.get(ins.getAddress()).get(0);
                sb.append(String.format("\n<tr><td align='left'>%X  %s</td></tr>", ins.getAddress() - moduleBase, ins));
                mergedNode.add(ins);
            }

            if (prepareImage) {
                MutableNode node = Factory.mutNode(Label.html("<table border='0'>" + sb.toString() + "</table>"))
                        .add(Shape.RECT, Style.ROUNDED);
                if (from != null) {
                    for (Instruction i : from) {
                        graphLinkMap.add(new Link(i.getAddress(), node));
                    }
                }
                graph.add(node);
                graphNodeMap.put(ins.getAddress(), node); // 记录，用于后续 graph 的链接
            }

            // 第二次探索之后可能会起到作用
            for (List<Instruction> block : mergedNodes)
                if (block.get(0).getAddress() == mergedNode.get(0).getAddress()) {
                    mergedNodes.remove(block);
                    break;
                }
            mergedNodes.add(mergedNode);

            if (toMap.get(ins.getAddress()) != null) {
                for (Instruction i : toMap.get(ins.getAddress())) {
                    if (!accessed.contains(i.getAddress())) {
                        pending.push(i);
                        accessed.add(i.getAddress());
                    }
                }
            }
        }

        if (prepareImage) {
            for (Link link : graphLinkMap) {
                MutableNode node = graphNodeMap.get(link.address);
                node.addLink(link.node);
            }
        }
    }

    public void splitBlockToControlAndReal(boolean prepareImage) {
        // 由于补充了新的分块，需要进行重置了
        controlNodes = new HashSet<>();
        realNodes = new HashSet<>();

        this.preDispather = getPreDispather();
        controlNodes.add(preDispather);
        System.out.println("preDispather: " + Long.toHexString(preDispather.get(0).getAddress()));
        for (Instruction ins : toMap.get(preDispather.get(preDispather.size() - 1).getAddress())) {
            List<Instruction> toBlock = getMergeNodeByStart(ins.getAddress());
            controlNodes.add(toBlock);
            assert toBlock != null;
            List<Instruction> matched = fuzzyMatchDispatch(toBlock);
            if (matched != null) {
                String otherReg = matched.get(0).getOpStr().split(",")[0];
                String[] regs = matched.get(2).getOpStr().split(",");
                reg = otherReg.equals(regs[0].trim())
                        ? regs[1].trim()
                        : regs[0].trim();
                System.out.printf("Find flag reg, %x reg: %s, ins: %s\n", ins.getAddress(), reg, matched);
            }
            // 有时候紧接着的节点不行，再往后找一个，如果说这个也不行，最好是手动赋值
            for (Instruction ins2: toMap.get(toBlock.get(toBlock.size() - 1).getAddress())) {
                List<Instruction> toBlock2 = getMergeNodeByStart(ins2.getAddress());
                controlNodes.add(toBlock2);
                List<Instruction> matched2 = fuzzyMatchDispatch(toBlock2);
                if (matched2 != null) {
                    String otherReg = matched2.get(0).getOpStr().split(",")[0];
                    String[] regs = matched2.get(2).getOpStr().split(",");
                    reg = otherReg.equals(regs[0].trim())
                            ? regs[1].trim()
                            : regs[0].trim();
                    System.out.printf("Find flag reg, %x reg: %s, ins: %s\n", ins.getAddress(), reg, matched2);
                    break;
                }
            }
        }

        // 获取所有分发器
//        if (reg == null)
//            throw new RuntimeException("flag reg is null");
        System.out.println("flag reg: " + reg);
        System.out.println(mergedNodes.size());
//        reg = "w8";
        for (List<Instruction> block: mergedNodes) {
            List<Instruction> matched = exactMatchDispatch(block, reg);
            if (matched != null) {
//                System.out.println("matched: " + matched);
                controlNodes.add(block);
            } else if (manualControlNodes.contains(block.get(0).getAddress() - moduleBase)) {
                controlNodes.add(block);
            } else if (block.get(block.size() - 1).getMnemonic().equals("br")) {
                controlNodes.add(block);
                System.err.println("this block is end with br, may be a control block " + Long.toHexString(block.get(0).getAddress() - moduleBase));
            }
        }

        for (List<Instruction> block: mergedNodes) {
            if (!controlNodes.contains(block)) {
                realNodes.add(block);
            } else {
                if (prepareImage) {
                    MutableNode node = graphNodeMap.get(block.get(block.size() - 1).getAddress());
                    node.add(Style.lineWidth(5), Color.RED);
                }
            }
        }
        System.out.println("control block " + controlNodes.size());
        System.out.println("real block " + realNodes.size());
    }

    public void mergeRealArea() {
        System.out.println("mergeRealArea");
        // address -- common used times
        // 从block area start开始遍历，area中的block不会重复（通过accessed保存）
        // 所以commonBlock这个map中 value > 1 的就是真正的common block

        commonBlock = new HashMap<>();
        blockAreaStart = new HashMap<>();
        startMapTokeyIns = new HashMap<>();

        mergeOneRealArea(entry, to -> {
            for (List<Instruction> block : controlNodes)
                if (block.get(0).getAddress() == to.getAddress())
                    return true;
            return false;
        });

        for (List<Instruction> block : realNodes) {
//            MutableNode curNode = graphNodeMap.get(block.get(block.size() - 1).getAddress());
            List<Instruction> from = fromMap.get(block.get(0).getAddress());
            if (from == null) {
                continue;
            }
            for (Instruction ins : from) {
                // 如果from block是控制块，那么就算是area start，才进行后续的处理
                List<Instruction> lastBlock = getMergeNodeByEnd(ins.getAddress());
                if (!controlNodes.contains(lastBlock)) {
                    continue;
                }
                // 将real area的首个块设置为blue
//                curNode.add(Style.lineWidth(5), Color.BLUE);
                mergeOneRealArea(block.get(0), to -> preDispather.get(0).getAddress() == to.getAddress());
            }
        }


        for (long key : commonBlock.keySet())
            if (commonBlock.get(key) != 1) {
                // commonBlock
                // commonBlock目前认为会是preDispatcher前驱，或者是另一个commonBlock前驱
                List<Instruction> block = getMergeNodeByStart(key);
                List<Instruction> to = toMap.get(block.get(block.size() - 1).getAddress());
                if (to == null || to.size() != 1)
                    throw new RuntimeException("unexpected common block form");
                long address = to.get(0).getAddress();
                if (!commonBlock.containsKey(address) && preDispather.get(0).getAddress() != address)
                    throw new RuntimeException("unexpected common block form");
                System.out.println("common block start: " + Long.toHexString(key));
            }
    }

    interface OutBlockJudge {
        boolean isOutBlock(Instruction to);
    }

    private void mergeOneRealArea(Instruction ins, OutBlockJudge outBlockJudge) {
        Set<Long> area = new HashSet<>();

        Set<Long> accessed = new HashSet<>();
        Stack<Instruction> pending = new Stack<>();  // 只存block的首个ins
        accessed.add(ins.getAddress());
        pending.add(ins);
        int outBlockNum = 0;
        Instruction assign = null;
        // 遍历整个block area
        while (!pending.empty()) {
            Instruction top = pending.pop();
            List<Instruction> b = getMergeNodeByStart(top.getAddress());

            for (Instruction i : b) {
                area.add(i.getAddress());

                // 其实主要是区别处要分支的block area，以及顺序的block area
//                if (i.toString().startsWith("add " + reg) && (assign == null || !assign.toString().startsWith("csel " + reg)))
//                    assign = i;
                if (i.toString().startsWith("csel " + reg))
                    assign = i;
//                if (i.toString().startsWith("movk " + reg))
//                    assign = i;
//                            System.out.println(Long.toHexString(i.getAddress() - moduleBase) + ": " + i);
            }

            // 计算block的命中次数，获取commonBlock
            int times = commonBlock.getOrDefault(top.getAddress(), 0);
            // 重复不止一次，代表是commonBlock
//            if (times != 0) {
//                graphNodeMap.get(b.get(b.size() - 1).getAddress()).add(Style.lineWidth(10), Color.PURPLE);
//            }
            commonBlock.put(top.getAddress(), times + 1);

            List<Instruction> toList = toMap.get(b.get(b.size() - 1).getAddress());
            if (toList != null)
                for (Instruction to : toList)
                    if (!accessed.contains(to.getAddress())) {
                        if (!outBlockJudge.isOutBlock(to)) {
                            pending.push(to);
                            accessed.add(to.getAddress());
                        } else {
                            // 这是顺便借个地方统计以下出口的数量
                            outBlockNum ++;
                        }
                    }
        }
        this.blockAreaStart.put(ins.getAddress(), area);

        if (assign != null) {
            System.out.println("assign instruction: " + Long.toHexString(assign.getAddress()) + " " + assign);
            startMapTokeyIns.put(ins.getAddress(), assign.getAddress());
        }
        if (outBlockNum > 1) {
            System.out.println("the multi out block is:");
            for (Instruction i : getMergeNodeByStart(ins.getAddress())) {
                System.out.println(Long.toHexString(i.getAddress() - moduleBase) + " " + i);
            }
            throw new RuntimeException("outBlockNum is not one: " + Long.toHexString(ins.getAddress() - moduleBase));
        }
    }

    public void linkRealBlock() {
        for (List<Instruction> block : realNodes) {
            // 这个是所有块的from，下面的是真实块之间的from
            boolean isStart = blockAreaStart.containsKey(block.get(0).getAddress());

            MutableNode curNode = graphNodeMap.get(block.get(block.size() - 1).getAddress());
            List<Instruction> from = realFromMap.get(block.get(0).getAddress());
            if (from != null) {
                for (Instruction ins : from) {
                    System.out.printf("real link: %x -> %x\n", ins.getAddress(), block.get(0).getAddress());
                    MutableNode lastNode = graphNodeMap.get(ins.getAddress());

//                    curNode.add(Style.lineWidth(5), isStart ? Color.GREEN : Color.BLUE);
//                    lastNode.add(Style.lineWidth(5), Color.BLUE);

                    lastNode.addLink(
                            Factory.to(curNode)
                                    .add(Style.lineWidth(5))
                                    .add(isStart ? Color.GREEN : Color.BLUE)
//                                    .add(Attributes.attr("weight", 10))
                    );
                }
            }
        }
    }

    public void patchInstructionAll() {
        // 地址和要修改为的指令
        // 1. 旧跳转指令的patch
        // 2. commonBlock的复制
        // 所以用过的 controlNode 地址是会在这里面保存的
        HashMap<Long, String> patchInfo = new HashMap<>();

        patchInstructionArea(patchInfo, entry, to -> {
            for (List<Instruction> block : controlNodes)
                if (block.get(0).getAddress() == to.getAddress())
                    return true;
            return false;
        });

        for (List<Instruction> block : realNodes) {
            List<Instruction> from = fromMap.get(block.get(0).getAddress());
            if (from == null) {
                continue;
            }
            for (Instruction ins : from) {
                // 如果from block是控制块，那么就算是area start，才进行后续的处理
                List<Instruction> lastBlock = getMergeNodeByEnd(ins.getAddress());
                if (!controlNodes.contains(lastBlock)) {
                    continue;
                }
                patchInstructionArea(patchInfo, block.get(0), to -> preDispather.get(0).getAddress() == to.getAddress());
            }
        }

        for (List<Instruction> block : controlNodes)
            for (Instruction ins : block)
                if (!patchInfo.containsKey(ins.getAddress() - moduleBase))
                    patchInfo.put(ins.getAddress() - moduleBase, "nop");

        for (long key : patchInfo.keySet())
            System.out.println("patch: [" + Long.toHexString(key) + "] " + patchInfo.get(key));

        for (long key : patchBrInfo.keySet())
            System.out.println("patch: [" + Long.toHexString(key) + "] " + patchBrInfo.get(key));
    }

    private Instruction allocBlock(List<Instruction> common, int size, Map<Long, String> patchInfo, Map<Long, Long> copyBlock) {
//        for (List<Instruction> controlNode : controlNodes) {
//            // 这里需要避免entry之后的控制块被分配了，因为它可能是接着的，是没有跳转指令来覆盖的
//            // 这个控制块一般是preDispatcher的后继
//            List<Instruction> from = fromMap.get(controlNode.get(0).getAddress());
//            boolean isLinkEntry = false;
//            for (Instruction f : from)
//                if (f.getAddress() == preDispather.get(preDispather.size() - 1).getAddress())
//                    isLinkEntry = true;
//            if (isLinkEntry)
//                continue;
//
//            if (controlNode.size() >= size && !patchInfo.containsKey(controlNode.get(0).getAddress() - moduleBase) && !copyBlock.containsValue(controlNode.get(0).getAddress())) {
//                return controlNode.get(0);
//            }
//        }

        // 倒着分配
        Instruction lastAlloc = null;
        int rest = size;
        // 对于没有一个区块能满足的
        for (List<Instruction> controlNode : controlNodes) {
//            // 这里需要避免entry之后的控制块被分配了，因为它可能是接着的，是没有跳转指令来覆盖的
//            // 这个控制块一般是preDispatcher的后继
//            List<Instruction> from = fromMap.get(controlNode.get(0).getAddress());
//            boolean isLinkEntry = false;
//            for (Instruction f : from)
//                if (f.getAddress() == preDispather.get(preDispather.size() - 1).getAddress())
//                    isLinkEntry = true;
//            if (isLinkEntry)
//                continue;
            // 这里需要进行普适，不只是entry块，所有和前面块联系的，都不能被分配，因为它要由前面的块直接使用
            List<Instruction> from = fromMap.get(controlNode.get(0).getAddress());
            boolean isDirectAfterRealBlock = false;
            for (Instruction f : from)
                if (f.getAddress() == controlNode.get(0).getAddress() + 4)
                    isDirectAfterRealBlock = true;
            if (isDirectAfterRealBlock)
                continue;

            // size - common.size() 是common块之外的，会有点对不起来，所以得手动处理
            // 理论上只有第一次分配，即分配尾部需注意，这里直接全做判断，简单一些
            if (controlNode.size() > 1 + (size - common.size()) && !patchInfo.containsKey(controlNode.get(0).getAddress() - moduleBase) && !copyBlock.containsValue(controlNode.get(0).getAddress())) {
//                return controlNode.get(0);
                if (lastAlloc != null) {
                    patchInfo.put(controlNode.get(Math.min(controlNode.size() - 1, rest + 1)).getAddress() - moduleBase, String.format("b %d", lastAlloc.getAddress() - moduleBase));
                }
                lastAlloc = controlNode.get(0);
                // 不同区块之间需要一个br指令去跳转下一个alloc区域
                rest = rest - (controlNode.size() - 1);
                if (rest <= 0) {
                    return lastAlloc;
                } else
                    copyBlock.put(common.get(rest + 1).getAddress(), controlNode.get(0).getAddress());
            }
        }
        return null;
    }

    private void patchInstructionArea(Map<Long, String> patchInfo, Instruction start, OutBlockJudge outBlockJudge) {
        int addition = condBlockAreaMap.containsKey(start.getAddress()) ? 1 : 0;
        Set<Long> area = new HashSet<>();

        // block 原有的到新的映射，在一次area中一个block只会被复制一次
        Map<Long, Long> copyBlock = new HashMap<>();
        Set<Long> accessed = new HashSet<>();
        Stack<Instruction> pending = new Stack<>();  // 只存block的首个ins
        accessed.add(start.getAddress());
        pending.add(start);
        // 遍历整个block area
        while (!pending.empty()) {
            Instruction top = pending.pop();
            List<Instruction> b = getMergeNodeByStart(top.getAddress());
            Instruction lastIns = b.get(b.size() - 1);
            long lastInsAddress = lastIns.getAddress();
            List<Instruction> toList = toMap.get(lastInsAddress);

            for (Instruction i : b)
                area.add(i.getAddress());

            if (toList != null) {
                if (commonBlock.getOrDefault(top.getAddress(), 0) > 1 && copyBlock.containsKey(top.getAddress())) {
                    // 遍历到commonBlock，此时copyBlock中已经包含了它的信息
                    List<Instruction> common = getMergeNodeByStart(top.getAddress());
                    long copyTo = copyBlock.get(top.getAddress());
                    long base = 0;
                    for (int i = 0; i < common.size(); i++, base ++) {
                        if (i != 0 && copyBlock.containsKey(common.get(i).getAddress())) {
                            copyTo = copyBlock.get(common.get(i).getAddress());
                            base = 0;
                        }
                        copyBlock.put(common.get(i).getAddress(), copyTo + base * 4L);
                        patchInfo.put(copyTo + i * 4L - moduleBase, common.get(i).toString().replaceAll("#0x400([0-9a-fA-F]+)", "#0x$1"));
                    }
                }

                for (Instruction to : toList) {
                    // commonBlock的格式在前面mergeRealArea判断过了
                    // 如果下个block是commonBlock，并且还不是紧接着的，那么需要复制
                    if (commonBlock.getOrDefault(to.getAddress(), 0) > 1 && copyBlock.getOrDefault(lastInsAddress, lastInsAddress) + 4 != to.getAddress()) {
                        List<Instruction> common = getMergeNodeByStart(to.getAddress());
                        // 由于至少要包含一个指令以及一个跳转指令，所以必须
                        // + 1 是为了避免一些问题（比如common下一个刚好是preDispatcher）
                        // 或者是连续的两个common块，复制出来之后前一个要加跳转，等等
                        // 总结是，如果不以b结尾，应该要改，所以要提前预备一个
                        int brAddition = common.get(common.size() - 1).getMnemonic().equals("b") ? 0 : 1;
                        Instruction alloc = allocBlock(common, common.size() + addition + brAddition, patchInfo, copyBlock);
                        if (alloc == null)
                            throw new RuntimeException("No enough controlNode " + Long.toHexString(common.get(0).getAddress()));
                        else {
                            // 连续common块，复制出来，需要patch，会走到这里面，但实际它是不以 b 指令结尾的，这里根据原指令筛除
                            if (!lastIns.getMnemonic().equals("b") && lastInsAddress + 4 != to.getAddress())
                                throw new RuntimeException("Unexpected last ins" + Long.toHexString(lastInsAddress) + " " + lastIns);
                            // 如果是copy的block，那么patch地址是 copyBlock.get(lastInsAddres)，否则就是lastInsAddress
                            // 所以用 copyBlock.getOrDefault(lastInsAddress, lastInsAddress) 即可
                            boolean needNewIns = !lastIns.getMnemonic().equals("b");
                            patchInfo.put(copyBlock.getOrDefault(lastInsAddress, lastInsAddress) + (needNewIns ? 4 : 0) - moduleBase,
                                    String.format("b %d", alloc.getAddress() - moduleBase));
                            copyBlock.put(to.getAddress(), alloc.getAddress());
                            System.out.printf("pre copy common block, patch %x, real patch %x, patch ins: %s\n",
                                    lastInsAddress + (needNewIns ? 4 : 0) - moduleBase,
                                    copyBlock.getOrDefault(lastInsAddress, lastInsAddress) + (needNewIns ? 4 : 0) - moduleBase,
                                    String.format("b %x", alloc.getAddress() - moduleBase));
                        }
                    }

                    if (!accessed.contains(to.getAddress()))
                        if (outBlockJudge.isOutBlock(to)) {
                            // 对于最后一个block，即out block（之前已经判断过一个area只有一个out block）
                            // 首先对于所有的要进行patch的，要先找到一个用于patch跳转的地址
                            // 1. 尾部直接存在b指令的，patch这个b即可
                            // 2. 没有b指令，entry块，而且to是下一条指令，且to是controlBlock，那么以下一条指令作为patch
                            // 3. 没有b指令，to是下一条指令，且to是preDispatcher，且当前是复制块，那么在尾部的下一条指令patch
                            // 4. 没有b指令，to是下一条指令，且to是preDispatcher，那么在尾部的下一条指令patch
                            // 剩下的是对于cond情况的真实块集合来说，需要一直往上找，直到在 startMapTokeyIns，过程中的指令暂存以下，然后开始 patch 这些指令（调整顺序）
                            System.out.println("last ins: " + lastIns);

                            long nextAddress = -1;
                            if (flowBlockAreaMap.containsKey(start.getAddress()))
                                nextAddress = flowBlockAreaMap.get(start.getAddress()).get(0).getAddress();
                            else if (condBlockAreaMap.containsKey(start.getAddress()))
                                // b.{cond} {trueAddr}
                                // b        {falseAddr}
                                nextAddress = condBlockAreaMap.get(start.getAddress()).get(0) == null ? -1 : condBlockAreaMap.get(start.getAddress()).get(0).getAddress();
                            if (nextAddress == -1)
//                                throw new RuntimeException("next address is null " + Long.toHexString(start.getAddress()));
                                continue;

                            String patchFlowInstruction = String.format("b %d", nextAddress - moduleBase);
                            Instruction willPatchCondInstruction = null;
                            if (lastIns.getMnemonic().equals("b")) {
                                // 这里是假定block大小是大于1的，碰到等于1的再想办法处理
                                willPatchCondInstruction = b.get(b.size() - 2);
                                patchInfo.put(copyBlock.getOrDefault(lastInsAddress, lastInsAddress) - moduleBase, patchFlowInstruction);
                            } else if (start.getAddress() == entry.getAddress()) {
                                if (toList.size() == 1 && toList.get(0).getAddress() == lastInsAddress + 4) {
                                    willPatchCondInstruction = lastIns;
                                    patchInfo.put(copyBlock.getOrDefault(toList.get(0).getAddress(), toList.get(0).getAddress()) - moduleBase, patchFlowInstruction);
                                } else
                                    throw new RuntimeException("Unknown entry block area format");
                            } else if (toList.size() == 1 && toList.get(0).getAddress() == preDispather.get(0).getAddress()) {
                                // 如果有复制的话，等后续再处理，这里只记原本的
                                willPatchCondInstruction = lastIns;
                                if (copyBlock.containsKey(top.getAddress())) {
                                    long targetPatchAddress = copyBlock.get(top.getAddress()) + b.size() * 4L;
                                    patchInfo.put(targetPatchAddress - moduleBase, patchFlowInstruction);
                                } else {
                                    patchInfo.put(preDispather.get(0).getAddress() - moduleBase, patchFlowInstruction);
                                }
                            } else
                                throw new RuntimeException("Unknown block area format " + Long.toHexString(start.getAddress()));


                            if (condBlockAreaMap.containsKey(start.getAddress()) && condBlockAreaMap.get(start.getAddress()).get(1) != null) {
                                List<Instruction> insBetweenKeyInsAndEnd = new ArrayList<>();
                                insBetweenKeyInsAndEnd.add(willPatchCondInstruction);
                                while (!startMapTokeyIns.containsValue(insBetweenKeyInsAndEnd.get(insBetweenKeyInsAndEnd.size() - 1).getAddress())) {
                                    Instruction cur = insBetweenKeyInsAndEnd.get(insBetweenKeyInsAndEnd.size() - 1);

                                    if (fromMap.containsKey(cur.getAddress())) {
//                                        List<Instruction> from = fromMap.get(cur.getAddress());
                                        // 如果是commonBlock，可能存在多个from，所以这里需要筛选一下
                                        Instruction fromInArea = null;
                                        for (Instruction f : fromMap.get(cur.getAddress()))
                                            if (area.contains(f.getAddress())) {
                                                if (fromInArea == null)
                                                    fromInArea = f;
                                                else
                                                    throw new RuntimeException("Find block area key ins error (multi from) " + Long.toHexString(cur.getAddress()) + " " + cur);
                                            }
                                        insBetweenKeyInsAndEnd.add(fromInArea);
                                    } else
                                        throw new RuntimeException("Find block area key ins error (no from) " + Long.toHexString(cur.getAddress()) + " " + cur);
                                }
                                // end .... ins
                                // end: b...
                                long trueAddress = condBlockAreaMap.get(start.getAddress()).get(1).getAddress();
                                Instruction keyIns = insBetweenKeyInsAndEnd.get(insBetweenKeyInsAndEnd.size() - 1);
                                String[] insInfoList = keyIns.toString().split(",");
                                String cond = insInfoList[insInfoList.length - 1].trim();
                                patchInfo.put(copyBlock.getOrDefault(willPatchCondInstruction.getAddress(), willPatchCondInstruction.getAddress()) - moduleBase,
                                        String.format("b.%s %d", cond, trueAddress - moduleBase));

                                // 创建一个临时的list，因为跳转指令不参与重排
                                List<Instruction> tmp = new ArrayList<>();
                                for (int i = 0; i < insBetweenKeyInsAndEnd.size(); i++)
                                    if (!insBetweenKeyInsAndEnd.get(i).getMnemonic().equals("b"))
                                        tmp.add(insBetweenKeyInsAndEnd.get(i));
                                // 从1开始，1 patch 0的，2 patch 1的
                                for (int i = 1; i < tmp.size(); i++) {
                                    patchInfo.put(copyBlock.getOrDefault(tmp.get(i).getAddress(), tmp.get(i).getAddress()) - moduleBase, tmp.get(i - 1).toString());
                                }
                            }
                            // out block process end

                        } else {
                            pending.push(to);
                            accessed.add(to.getAddress());
                        }
                }
            }
        }
    }

    public void outputImage(String filename) {
        for (long key : flowBlockAreaMap.keySet()) {
            System.out.printf("flow block: %x -> %x\n", key - moduleBase, flowBlockAreaMap.get(key).get(0).getAddress() - moduleBase);
        }
        for (long key : condBlockAreaMap.keySet()) {
            System.out.printf("cond block: %x -> true %x, false %x\n",
                    key - moduleBase,
                    condBlockAreaMap.get(key).get(1) == null ? null : condBlockAreaMap.get(key).get(1).getAddress() - moduleBase,
                    condBlockAreaMap.get(key).get(0) == null ? null : condBlockAreaMap.get(key).get(0).getAddress() - moduleBase);
        }
        try {
            Graphviz.fromGraph(graph).render(Format.SVG).toFile(new File(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }






    private void addNode(Instruction ins) {
        boolean include = false;
        for (Instruction i : nodes)
            if (i.getAddress() == ins.getAddress()) {
                include = true;
                break;
            }
        if (!include)
            nodes.add(ins);
    }

    private void putLinkToMap(Map<Long, List<Instruction>> map, long address, Instruction ins) {
        if (!map.containsKey(address)) {
            map.put(address, new ArrayList<>());
        }

        boolean include = false;
        for (Instruction i : map.get(address))
            if (i.getAddress() == ins.getAddress()) {
                include = true;
                break;
            }
        if (!include)
            map.get(address).add(ins);
    }

    private boolean canMerge(Instruction ins) {
        long address = ins.getAddress();
        List<Instruction> to = toMap.get(address);
        if (to == null || to.size() != 1) {
            return false;
        }
        // 如果下一节点的from只有当前这个元素，认为可合并
        return fromMap.get(to.get(0).getAddress()).size() == 1 && to.get(0).getAddress() <= ins.getAddress() + 4;
    }

    private List<Instruction> getPreDispather() {
        List<Instruction> result = null;
        for (List<Instruction> node : mergedNodes) {
            if (result == null) {
                result = node;
            } else {
                List<Instruction> resultFrom = fromMap.get(result.get(0).getAddress());
                List<Instruction> nodeFrom = fromMap.get(node.get(0).getAddress());
                int resultFromLen = resultFrom == null ? 0 : resultFrom.size();
                int nodeFromLen = nodeFrom == null ? 0 : nodeFrom.size();
                if (nodeFromLen > resultFromLen) {
                    result = node;
                }
            }
            List<Instruction> to = toMap.get(node.get(node.size() - 1).getAddress());
            if (to == null) {
                System.out.println("ret block" + node);
            }
        }
        return result;
    }

    private List<Instruction> getMergeNodeByStart(long start) {
        for (List<Instruction> ins : mergedNodes)
            if (ins.get(0).getAddress() == start)
                return ins;
        return null;
    }
    private List<Instruction> getMergeNodeByEnd(long end) {
        for (List<Instruction> ins : mergedNodes)
            if (ins.get(ins.size() - 1).getAddress() == end)
                return ins;
        return null;
    }

    // 如果一个block符合有符合下面格式的指令，那么就返回cmp指令，否则返回null;
    // 如果有flagReg，那么就是精确匹配模式
    // 保证cmp大于base，目的是处理只有cmp的块，正常写0就行
    //    mov        w10, #0xded1
    //    movk       w10, #0x56da, LSL #16
    //    cmp        w8, w10
    private List<Instruction> fuzzyMatchDispatch(List<Instruction> block) {
        return matchDispatch(block, null, 0);
    }
    private List<Instruction> exactMatchDispatch(List<Instruction> block, String flagReg) {
        List<Instruction> matched = matchDispatch(block, flagReg, 0);
        if (matched == null) {
            Stack<List<Instruction>> allFrom = new Stack<>();
            List<Instruction> fromList = fromMap.get(block.get(0).getAddress());
            while (fromList != null && fromList.size() == 1) {
                List<Instruction> fromBlock = getMergeNodeByEnd(fromList.get(0).getAddress());
                allFrom.push(fromBlock);
                fromList = fromBlock == null ? null : fromMap.get(fromBlock.get(0).getAddress());
            }

            if (allFrom.empty()) {
                return matched;
            }
            List<Instruction> mergeBlock = new ArrayList<>();
            while (!allFrom.empty())
                mergeBlock.addAll(allFrom.pop());
            mergeBlock.addAll(block);
            matched = matchDispatch(mergeBlock, flagReg, mergeBlock.size() - block.size());
        }
        return matched;
    }
    private List<Instruction> matchDispatch(List<Instruction> block, String flagReg, int base) {
        List<List<Instruction>> matched = new ArrayList<>();
        for (int i = 0; i < block.size(); i++) {
            Instruction ins = block.get(i);
            if (ins.getMnemonic().equals("mov") && ins.getOpStr().contains("#0x")) {
                List<Instruction> tmp = new ArrayList<>();
                tmp.add(ins);
                matched.add(tmp);
            } else if (ins.getMnemonic().equals("movk") && ins.getOpStr().split(",")[1].contains("#0x")) {
                String reg = ins.getOpStr().split(",")[0];
                List<Instruction> regSame = null;
                for (List<Instruction> list : matched)
                    if (list.size() == 1 && list.get(0).getOpStr().split(",")[0].trim().equals(reg)) {
                        regSame = list;
                        break;
                    }
                if (regSame != null)
                    regSame.add(ins);
            } else if (ins.getMnemonic().equals("cmp") && i >= base) {
                // 如果cmp的数字也不影响，因为后续对比会不成功
                String reg1 = ins.getOpStr().split(",")[0].trim();
                String reg2 = ins.getOpStr().split(",")[1].trim();
                List<Instruction> regSame = null;
                for (List<Instruction> list : matched) {
                    if (list.size() == 2) {
                        // 没有提前储存，直接和list第一个中包含的reg比，即 list.get(0).getOpStr().split(",")[0].trim()
                        String storeReg = list.get(0).getOpStr().split(",")[0].trim();
                        if (flagReg == null && (storeReg.equals(reg1) || storeReg.equals(reg2))) {
                            regSame = list;
                            break;
                        }
                        // 指定了flagReg，那么一个需要和list中的匹配，一个需要和flagReg一样
//                        System.out.println(flagReg + " " + storeReg + ", " + reg1 + " " + reg2);
                        if (flagReg != null &&
                                ((storeReg.equals(reg1) && flagReg.equals(reg2)) ||
                                        (storeReg.equals(reg2) && flagReg.equals(reg1)))) {
                            regSame = list;
                            break;
                        }
                    }
                }
                if (regSame != null) {
                    regSame.add(ins);
                    return regSame;
                }
            }
        }
        return null;
    }

    class Link {
        long address;
        MutableNode node;
        public Link(long address, MutableNode node) {
            this.address = address;
            this.node = node;
        }

//        @Override
//        public boolean equals(Object obj) {
//            if (this == obj) return true;
//            if (obj == null || getClass() != obj.getClass()) return false;
//            Link that = (Link) obj;
//            return address == that.address && Objects.equals(node, that.node);
//        }
//
//        @Override
//        public int hashCode() {
//            return Objects.hash(address, node);
//        }
    }
}
