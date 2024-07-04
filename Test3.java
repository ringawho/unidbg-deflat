package com.wuaipojie;

import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.SystemPropertyProvider;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import guru.nidi.graphviz.attribute.*;
import guru.nidi.graphviz.model.Factory;
import guru.nidi.graphviz.model.Graph;
import unicorn.Arm64Const;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Test3 {
    private AndroidEmulator emulator;
    private VM vm;
    private Module module;
    private final JSONObject cmdMap = getCmdMap();
    private final JSONObject condBranchMap = new JSONObject();
    private final JSONObject branchLinkMap = new JSONObject();
    private int[] regIDs = ARM.getAll64Registers();

    // 作用1: nzcv节点之间的instruction可能存在死循环，需要通过这个保存遍历过得ins，避免重复
    // 作用2: 保存了历史ins，可以创建link
    // 进行下一个节点之前会清除，但是会保留尾部的一个，保证link的创建
    private List<Instruction> accessedInstructions = new ArrayList<>();
    private List<Instruction> accessedRealInstructions = new ArrayList<>();
    private List<Instruction> accessedStartInstructions = new ArrayList<>();
    private List<Node> currentPath = null;
    private int curNodeIndex = 0;
    private Set<String> accessedNodeInCommonBlock = new HashSet<>();
    private Status explorerStatus = Status.RUNNING;
    // 将探索过的nzcv节点记录下来，减少重复探索，同时也避免了这些节点之间构成死循环
    // 加上accessedInstructions的存在，基本上可以避免死循环的出现
    private Map<Long, Integer> accessedNode = new HashMap<>();


    private Set<String> edges = new HashSet<>();
    private Graph graph = Factory.graph("example1").directed()
            .graphAttr().with(Rank.dir(Rank.RankDir.TOP_TO_BOTTOM))
            .nodeAttr().with(Font.name("monospace"))
            .linkAttr().with("class", "link-class");

    private InstructionGraph instructionGraph = new InstructionGraph();
    private boolean onlyRealBlock = false;

    private long start = 0;
    private long end = 0;

    enum Status {
        RUNNING,
        END,
        INS_INFINITE_LOOP,
        NODE_INFINITE_LOOP,
        NODE_IN_COMMON_INFINITE_LOOP,
        NODE_MULTI_RUNNING_INFINITE_LOOP,
        ALREADY_EXPLORER_COMPLETED,  // 最新的node之前已经探索过了
        NO_REAL_BLOCK
    }

    class Node {
        long address;
        boolean cond;

        public Node(long address, boolean cond) {
            this.address = address;
            this.cond = cond;
        }

        @Override
        public String toString() {
            return String.format("%x %s", address, cond);
        }
    }

    public Test3() {
//        init();
    }

    public void setHookRegion(int start, int end) {
        this.start = start;
        this.end = end;
    }

    public void init() {
        this.emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.lib52pojie.so.crackme2024")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        Memory memory = setupMemory();

        new Camera(emulator, null).register(memory);

        vm = emulator.createDalvikVM();
        vm.setVerbose(false);

        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/wuaipojie/lib52pojie.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        instructionGraph.setModuleBase(module.base);

        emulator.getBackend().hook_add_new(new CodeHook() {
            boolean keyInsCondSuc = false;
//            boolean logIns = false;

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long offset = address - module.base;
                Instruction ins = emulator.disassemble(address, size, 0)[0];

//                if (onlyRealBlock && offset == 0x1FFDC)
//                    logIns = true;
//                if (logIns)
//                    System.out.printf("[%x] %s\n", ins.getAddress(), ins);

                try {
                    if (ins.getMnemonic().equals("blr")) {
                        OpInfo opInfo = (OpInfo) ins.getOperands();
                        Operand operand = opInfo.getOperands()[0];
                        assert operand.getType() == Arm64_const.ARM64_OP_REG;
                        if (operand.getType() == Arm64_const.ARM64_OP_REG) {
                            int reg = ins.mapToUnicornReg(operand.getValue().getReg());
                            long branchAddr = backend.reg_read(reg).longValue();

                            Module branchModule = memory.findModuleByAddress(branchAddr);
                            if (branchAddr >= module.base && branchAddr <= module.base + module.size) {
                                instructionGraph.setBrInfo(offset, branchAddr - module.base);
                            } else if (branchModule != null) {
                                Symbol symbol = branchModule.findClosestSymbolByAddress(branchAddr, true);
                                long symbolAddr = branchModule.findSymbolByName(symbol.toString()) != null ? branchModule.findSymbolByName(symbol.toString()).getAddress() : -1;
                                System.out.printf("[%6X] blr %s\n", offset, symbolAddr == branchAddr ? module.name + " " + symbol.getName() : " can not be trusted! maybe jni function");
                            } else {
                                System.out.printf("[%6X] Not find Module, may be virtual module\n", offset);
                            }
                        }
                    }

                    if (!accessedInstructions.isEmpty()) {
                        Instruction last = accessedInstructions.get(accessedInstructions.size() - 1);
                        instructionGraph.addLink(last, ins);

                        if (!instructionGraph.isInRealBlock(last.getAddress()) && instructionGraph.isPreDispatcher(address)) {
                            // 直接在控制块之间构成死循环了，中间没有真实块，这样控制变量就不变化了
                            explorerStatus = Status.NO_REAL_BLOCK;
                            return;
                        }
//                    String edge = address + "-" + last.getAddress();
//                    if (!edges.contains(edge)) {
//                        graph = graph.with(
//                                Factory.node(String.format("%x %s", last.getAddress(), last))
//                                        .with(Shape.RECT).with(Style.ROUNDED)
//                                        .link(Factory.node(String.format("%x %s", address, ins))
//                                                .with(Shape.RECT).with(Style.ROUNDED))
//                        );
//                        edges.add(edge);
//                    }
                    }
                    if (onlyRealBlock && instructionGraph.isInRealBlock(address) && !accessedRealInstructions.isEmpty()) {
                        Instruction last = accessedRealInstructions.get(accessedRealInstructions.size() - 1);
                        instructionGraph.addRealLink(last, ins);
                    }
                    if (onlyRealBlock && instructionGraph.isBlockAreaStartOrEntry(address) && !accessedStartInstructions.isEmpty()) {
                        Instruction last = accessedStartInstructions.get(accessedStartInstructions.size() - 1);
                        instructionGraph.addBlockAreaLink(last, ins, keyInsCondSuc);
                    }

                    // 在添加 link 之后才退出，保证都死循环也可以 link 到
                    if (explorerStatus != Status.RUNNING) {
                        emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, -10);
                        return;
                    }
                    if (ins.getMnemonic().equals("ret")) {
                        // 如果当前函数会执行多次，那么这个ret会在下次重进函数是被连起来，所以这里要直接设置退出
                        emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, -10);
                        explorerStatus = Status.END;
                    }


                    for (Instruction i : onlyRealBlock ? accessedRealInstructions : accessedInstructions)
                        if (i.getAddress() == address) {
                            // 死循环的需要正确串起来，所以这里需要加ins
                            accessedInstructions.add(ins);
                            if (onlyRealBlock && instructionGraph.isInRealBlock(address)) {
                                accessedRealInstructions.add(ins);
                            }
                            if (onlyRealBlock && instructionGraph.isBlockAreaStartOrEntry(address)) {
                                accessedStartInstructions.add(ins);
                            }

                            if (!instructionGraph.isCommonBlockIns(address)) {
                                explorerStatus = Status.INS_INFINITE_LOOP;
                                return;
                            }
                            break;
                        }

                    // 上面也有一个加指令的行，如果条件要改就都得改
                    accessedInstructions.add(ins);
                    if (onlyRealBlock && instructionGraph.isInRealBlock(address)) {
                        accessedRealInstructions.add(ins);
                    }
                    if (onlyRealBlock && instructionGraph.isBlockAreaStartOrEntry(address)) {
                        accessedStartInstructions.add(ins);
                    }


                    short[] read = ins.regsAccess().getRegsRead();

                    // && !isExcludeNZCV(offset)
                    if (hasNZCV(ins, read) && (!onlyRealBlock || instructionGraph.isInRealBlock(address))) {
                        // 由于记录link的时候是用这个的，所以每次需要留一个，保证能正确link
                        // 但是它本身是为了避免每个nzcv的节点之间存在死循环，所以留一个有风险，出现死循环需考虑这里
                        if (onlyRealBlock)
                            accessedRealInstructions = accessedRealInstructions.subList(accessedRealInstructions.size() - 1, accessedRealInstructions.size());
                        else
                            accessedInstructions = accessedInstructions.subList(accessedInstructions.size() - 1, accessedInstructions.size());

//                        System.err.println(String.format("explorer: %X %s %s", address, ins, currentPath));
                        // 由于第二遍探索，有一些commonBlock中的应该被遍历多遍，结果只被遍历一遍，特别排除一下
                        if (!instructionGraph.isCommonBlockIns(address)) {
                            for (int i = 0; i < currentPath.size(); i++)
                                if (i != curNodeIndex && currentPath.get(i).address == offset) {
                                    explorerStatus = Status.NODE_INFINITE_LOOP;
                                    return;
                                }
                        } else {
                            Instruction areaStart = accessedStartInstructions.get(accessedStartInstructions.size() - 1);
                            String key = areaStart.getAddress() + "-" + address;
                            if (accessedNodeInCommonBlock.contains(key)) {
                                explorerStatus = Status.NODE_IN_COMMON_INFINITE_LOOP;
                                return;
                            }
                            accessedNodeInCommonBlock.add(key);
                        }

                        String condStr = getCond(ins);
                        Cpsr cpsr = Cpsr.getArm64(backend);
                        boolean cond = isCondSuc(condStr, cpsr);
                        if (curNodeIndex < currentPath.size() && currentPath.get(curNodeIndex).address != offset) {
                            System.err.println(String.format("Unexpected address: %X %s %s", address, ins, currentPath));
                        }
                        if (curNodeIndex < currentPath.size() && currentPath.get(curNodeIndex).cond != cond) {
                            toggleCpsrStatus(condStr, cpsr);
                        }
                        if (curNodeIndex >= currentPath.size()) {
                            if (!cond) {
                                toggleCpsrStatus(condStr, cpsr);
                            }
                            // 新节点处理true的情况
                            currentPath.add(new Node(offset, true));
                        }

                        if (instructionGraph.isKeyIns(address)) {
                            System.out.println("is key ins: " + Long.toHexString(offset));
                            keyInsCondSuc = isCondSuc(condStr, cpsr);
                            if (offset == 0x25e60)
                                System.out.println("special key ins: " + keyInsCondSuc);
                        }

                        // 新增（由于上面add了，所以也是size - 1）或者是结尾是false的
                        // 增加这个条件，会让后面跑全量的
                        // !onlyRealBlock &&
                        if (curNodeIndex == currentPath.size() - 1 && !instructionGraph.isCommonBlockIns(address)) {
                            int accessedInfo = accessedNode.getOrDefault(offset, 0);
                            int trueStatus = accessedInfo & 0xf;
                            int falseStatus = accessedInfo >> 4;
                            boolean suc = isCondSuc(condStr, cpsr);
                            if (trueStatus == 1 || falseStatus == 1) {
                                // 已经有节点在running了，那么就代表本次探索已经构成了死循环，可停止探索
                                System.out.println(String.format("%X is already explorer", address));
                                explorerStatus = Status.NODE_MULTI_RUNNING_INFINITE_LOOP;
                                return;
                            } else if ((suc && trueStatus == 3) || (!suc && falseStatus == 3)) {
                                // true, false 分支均探索完，无需继续探索
                                System.out.println(String.format("%X is already explorer", address));
                                explorerStatus = Status.ALREADY_EXPLORER_COMPLETED;
                                return;
                            } else if (accessedInfo == 0) {
                                if (!suc)
                                    System.err.println("cond should be success " + Long.toHexString(offset) + ", ins is: " + ins);
                                accessedNode.put(offset, 1);
                            } else if (falseStatus == 0) {
                                if (suc)
                                    System.err.println("cond should be true " + Long.toHexString(offset) + ", ins is: " + ins);
                                accessedNode.put(offset, (accessedInfo & 0x0f) | 0x10);
                            } else {
                                // 这里就是处理之前失败过的节点，让它重新恢复running
                                if (suc) {
                                    if (trueStatus != 2)
                                        System.err.println("trueStatus should be failed " + Long.toHexString(offset) + ", ins is: " + ins);
                                    accessedNode.put(offset, (falseStatus << 4) | 1);
                                } else {
                                    if (falseStatus != 2)
                                        System.err.println("falseStatus should be failed " + Long.toHexString(offset) + ", ins is: " + ins);
                                    accessedNode.put(offset, 0x10 | trueStatus);
                                }
                            }
                        }
                        curNodeIndex ++;
                    }
                } catch (Exception e) {
                    System.out.printf("ERROR: %X %s %s%n", address, ins, e.getMessage());
                    e.printStackTrace();
                }
//                System.out.println(String.format("%X", address));
            }

            @Override
            public void onAttach(UnHook unHook) {}

            @Override
            public void detach() {}
        }, module.base + this.start, module.base + this.end, null);

//        HookZz hook = HookZz.getInstance(emulator);
//        hook.replace(module.base + 0x1efe4, new ReplaceCallback() {
//            @Override
//            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
////                return super.onCall(emulator, context, originFunction);
//                return HookStatus.RET(emulator, context.getLR());
//            }
//        });
//        emulator.traceCode(0x2a5c8 + module.base, 0x2ab30 + module.base);
//        emulator.traceCode(0x2888c + module.base, 0x290cc + module.base);
//        emulator.traceCode(0x20cc8 + module.base, 0x20d58 + module.base);
    }

    private Memory setupMemory() {
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        SystemPropertyHook systemPropertyHook = new SystemPropertyHook(emulator);
        systemPropertyHook.setPropertyProvider(new SystemPropertyProvider() {
            @Override
            public String getProperty(String key) {
                if (key.equals("init.svc.adbd")) {
                    System.out.println("adbd stopped");
                    return "stopped";
//                    return "running";
                }
                return null;
            }
        });
        memory.addHookListener(systemPropertyHook);
        return memory;
    }

    public void destory() throws IOException {
        emulator.close();
    }

    public byte[] getMd5(String str) {
        try {
            return MessageDigest.getInstance("MD5").digest(str.getBytes());
        } catch (Exception unused) {
            return null;
        }
    }

    private void checkSn() {
        DvmObject<?> dvmObject = vm.resolveClass("com/wuaipojie/crackme2024/MainActivity").newObject(null);
        byte[] bArr = getMd5("00000001");
        String f = new String(new char[100]).replace("\0", "q");
        boolean result = dvmObject.callJniMethodBoolean(emulator, "checkSn([BLjava/lang/String;)Z", bArr, f);
        System.out.println("result: " + result);
    }

    private JSONObject getCmdMap() {
        String filePath = "/home/ring/reverse_workspace/py-rizin/cmd_map.json";
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return JSONObject.parseObject(sb.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return  null;
    }

    private String getCond(Instruction ins) {
        String[] opList = ins.getOpStr().split(",");
        String op = ins.getMnemonic();
        if (op.equals("cbz") || op.equals("cbnz")) {
            short[] read = ins.regsAccess().getRegsRead();
            if (read.length != 2) {
                throw new RuntimeException(op + ": unexpected the num of read reg");
            }
            int reg0 = ins.mapToUnicornReg(read[0]);
            int reg1 = ins.mapToUnicornReg(read[1]);
            int reg = reg0 == Arm64Const.UC_ARM64_REG_NZCV ? reg1 : reg0;
            return String.format("%s %d", op, reg);
        } else if (op.equals("tbz") || op.equals("tbnz")) {
            short[] read = ins.regsAccess().getRegsRead();
            int reg = ins.mapToUnicornReg(read[0]);
            int imm = Integer.decode(opList[1].trim().substring(1));
            return String.format("%s %d %d", op, reg, imm);
        } else if (op.startsWith("b.")) {
            return op.split("\\.")[1];
        }
        return opList[opList.length - 1].trim();
    }

    private boolean hasNZCV(Instruction ins, short[] regs) {
        String op = ins.getMnemonic();
        // 这几个指令是直接进行判断进行跳转的，不会先设置nzcv寄存器，然后在后面读取，所以要单独处理
        if (op.equals("cbz") || op.equals("cbnz") || op.equals("tbz") || op.equals("tbnz")) {
            return true;
        }
        for (short r : regs) {
            if (ins.mapToUnicornReg(r) == Arm64Const.UC_ARM64_REG_NZCV) {
                return true;
            }
        }
        return false;
    }

    // https://developer.arm.com/documentation/dui0801/l/Condition-Codes/Condition-code-suffixes-and-related-flags?lang=en
    private boolean isCondSuc(String condInfo, Cpsr cpsr) {
        String[] condList = condInfo.split(" ");
        String cond = condList[0];
        switch (cond) {
            case "eq": return cpsr.isZero();
            case "ne": return !cpsr.isZero();
            case "cs":
            case "hs": return cpsr.hasCarry();
            case "cc":
            case "lo": return !cpsr.hasCarry();
            case "mi": return cpsr.isNegative();
            case "pl": return !cpsr.isNegative();
            case "vs": return cpsr.isOverflow();
            case "vc": return !cpsr.isOverflow();
            case "hi": return cpsr.hasCarry() && !cpsr.isZero();
            case "ls": return !cpsr.hasCarry() || cpsr.isZero();
            case "ge": return cpsr.isNegative() == cpsr.isOverflow();
            case "lt": return cpsr.isNegative() != cpsr.isOverflow();
            case "gt": return !cpsr.isZero() && cpsr.isNegative() == cpsr.isOverflow();
            case "le": return cpsr.isZero() || cpsr.isNegative() != cpsr.isOverflow();
            case "cbz":
                int reg1 = Integer.parseInt(condList[1]);
                if (reg1 >= Arm64Const.UC_ARM64_REG_W0 && reg1 <= Arm64Const.UC_ARM64_REG_W30) {
                    return ((long) emulator.getBackend().reg_read(reg1) & 0xffffffffL) == 0L;
                }
                return (long) emulator.getBackend().reg_read(reg1) == 0L;
            case "cbnz":
                int reg2 = Integer.parseInt(condList[1]);
                if (reg2 >= Arm64Const.UC_ARM64_REG_W0 && reg2 <= Arm64Const.UC_ARM64_REG_W30) {
                    return ((long) emulator.getBackend().reg_read(reg2) & 0xffffffffL) != 0L;
                }
                return (long) emulator.getBackend().reg_read(reg2) != 0L;
            case "tbz": return (((long) emulator.getBackend().reg_read(Integer.parseInt(condList[1])) >> Integer.parseInt(condList[2])) & 1) == 0;
            case "tbnz": return (((long) emulator.getBackend().reg_read(Integer.parseInt(condList[1])) >> Integer.parseInt(condList[2])) & 1) != 0;
            case "al": return true;
        }
        throw new RuntimeException("unknown cond");
    }

    private void toggleCpsrStatus(String condInfo, Cpsr cpsr) {
        boolean condSuc = isCondSuc(condInfo, cpsr);
        String[] condList = condInfo.split(" ");
        String cond = condList[0];
        switch (cond) {
            case "eq":
            case "ne": cpsr.setZero(!cpsr.isZero()); break;
            case "cs":
            case "hs":
            case "cc":
            case "lo": cpsr.setCarry(!cpsr.hasCarry()); break;
            case "mi":
            case "pl": cpsr.setNegative(!cpsr.isNegative()); break;
            case "vs":
            case "vc": cpsr.setOverflow(!cpsr.isOverflow()); break;
            case "hi": cpsr.setCarry(!cpsr.hasCarry()); break;
            case "ls":
                if (condSuc) {
                    cpsr.setCarry(true);
                    cpsr.setZero(false);
                } else {
                    cpsr.setZero(true);
                }
                break;
            case "ge":
            case "lt": cpsr.setNegative(!cpsr.isNegative()); break;
            case "gt": cpsr.setZero(!cpsr.isZero()); break;
            case "le":
                if (condSuc) {
                    cpsr.setZero(false);
                    cpsr.setNegative(false);
                    cpsr.setOverflow(false);
                } else {
                    cpsr.setZero(true);
                }
                break;
            case "cbz":
            case "cbnz":
                int reg1 = Integer.parseInt(condList[1]);
                long origin = (long) emulator.getBackend().reg_read(reg1);
                if (reg1 >= Arm64Const.UC_ARM64_REG_W0 && reg1 <= Arm64Const.UC_ARM64_REG_W30) {
                     origin &= 0xffffffffL;
                }
                int value1 = origin == 0L ? 1 : 0;
                emulator.getBackend().reg_write(reg1, value1);
                break;
            case "tbz":
            case "tbnz":
                int reg = Integer.parseInt(condList[1]);
                int bit = Integer.parseInt(condList[2]);
                long value = (long) emulator.getBackend().reg_read(reg) ^ (1L << bit);
                emulator.getBackend().reg_write(reg, value);
                break;
            case "al":
            default:
                throw new RuntimeException("unknown cond");
        }
    }

    private void explorer(List<Node> path) {
//        path = new ArrayList<>();
//        path.add(new Node(0x1bf5c, true));
//        path.add(new Node(0x1bf64, true));
//        path.add(new Node(0x1bf78, true));
        String origin = path.toString();
        int originSize = path.size();
        this.currentPath = path;
        this.curNodeIndex = 0;
        this.accessedNodeInCommonBlock = new HashSet<>();
        this.explorerStatus = Status.RUNNING;
        this.accessedInstructions = new ArrayList<>();
        this.accessedRealInstructions = new ArrayList<>();
        this.accessedStartInstructions = new ArrayList<>();
        try {
            this.init();
            this.checkSn();
        } catch (Exception ignored) {}

        try {
            this.destory();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if (this.explorerStatus == Status.RUNNING) {
            Instruction ins = this.accessedInstructions.get(this.accessedInstructions.size() - 1);
            System.out.println("Unexpected exit: " + Long.toHexString(ins.getAddress()) + " " + ins + ", status is: " + this.explorerStatus);
        } else {
            Instruction ins = this.accessedInstructions.get(this.accessedInstructions.size() - 1);
            System.out.println("exit: " + Long.toHexString(ins.getAddress()) + " " + ins + ", status is: " + this.explorerStatus);
        }
        int targetStatus = this.explorerStatus == Status.RUNNING ? 2 : 3;
        for (Node n : this.currentPath) {
            long key = n.address;
            if (!accessedNode.containsKey(key))
                continue;
            int value = accessedNode.get(key);
            int trueStatus = value & 0xf;
            int falseStatus = value >> 4;
            if (n.cond)
                accessedNode.put(key, (falseStatus << 4) | targetStatus);
            else
                accessedNode.put(key, (targetStatus << 4) | trueStatus);
        }

        System.out.println("origin path: " + origin);
        System.out.println("result path: " + this.currentPath);
        System.out.println("---------------------");

        List<Node> tmpPath = this.currentPath;
        for (int i = tmpPath.size() - 1; i >= originSize; i--) {
            if (tmpPath.get(i).cond) {
                List<Node> newPath = new ArrayList<>();
                for (int j = 0; j < i; j++) {
                    newPath.add(new Node(tmpPath.get(j).address, tmpPath.get(j).cond));
                }
                newPath.add(new Node(tmpPath.get(i).address, false));
                explorer(newPath);
            }
        }
    }


    public static void main(String[] args) {
        // 创建一个 DateTimeFormatter 对象，用于格式化日期时间
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

        // 使用 DateTimeFormatter 对象将 LocalDateTime 对象格式化为字符串，并打印输出
        System.out.println("start time: " + LocalDateTime.now().format(formatter));
        Test3 test = new Test3();
//        test.setHookRegion(0x1befc, 0x1cf38);
//        test.setHookRegion(0x1e24c, 0x1e858);
//        test.setHookRegion(0x1e924, 0x2101c);
//        test.setHookRegion(0x221b4, 0x227c4);
//        test.setHookRegion(0x24290, 0x25ed4);
        test.setHookRegion(0x2a5c8, 0x2ab30);
        try {
//            test.checkSn();


            test.instructionGraph.setManualControlNodes(new long[]{
                    // ========================== 0x1e924 ==========================
                    // 开头dispatch之后的两个碎片
                    0x1f14c, 0x1f150,
                    // outblocknum抛错得到的
                    0x20b08, 0x20230, 0x20D5C, 0x204B0, 0x205E8, 0x20C60, 0x20CB0,
                    0x20810, 0x204CC, 0x20648, 0x1FD40, 0x20BEC, 0x20684,
                    // Unknown block area format 40020058
                    0x20058, 0x203C0, 0x20138,
                    // 通过control block不以br结尾发现的
                    0x202B4,
                    // ========================== 0x221b4 ==========================
                    0x2238C, 0x22390,
                    // ========================== 0x24290 ==========================
                    0x24A18, 0x24A1C,
                    // ========================== 0x2a5c8 ==========================
                    0x2A6D0, 0x2AAE4
            });

            test.explorer(new ArrayList<>());
            test.instructionGraph.findEntry();
            test.instructionGraph.mergeNodes(false);
            // 出错的话，用这两个提前获取图
//            test.instructionGraph.mergeNodes(true);
//            test.instructionGraph.outputImage("example/ex1m.svg");
            test.instructionGraph.splitBlockToControlAndReal(false);
            System.out.println("first explorer end =========================");
            test.instructionGraph.mergeRealArea();

            test.accessedNode = new HashMap<>();
            test.onlyRealBlock = true;
            test.explorer(new ArrayList<>());
            test.instructionGraph.mergeNodes(false);
            test.instructionGraph.splitBlockToControlAndReal(false);
            test.instructionGraph.mergeRealArea();

            test.accessedNode = new HashMap<>();
            test.onlyRealBlock = true;
            test.explorer(new ArrayList<>());
            test.instructionGraph.mergeNodes(true);
            test.instructionGraph.splitBlockToControlAndReal(true);
            test.instructionGraph.mergeRealArea();

            test.instructionGraph.linkRealBlock();
            test.instructionGraph.patchInstructionAll();
            test.instructionGraph.outputImage("example/ex1m.svg");

//            test.destory();
        } catch (Exception e) {
//            test.emulator.showRegs();
            e.printStackTrace();
        }
        System.out.println(test.condBranchMap.toJSONString());
        System.out.println(test.branchLinkMap.toJSONString());
        System.out.println("end time: " + LocalDateTime.now().format(formatter));

//        try {
//            Graphviz.fromGraph(test.graph).height(100).render(Format.SVG).toFile(new File("example/ex1.svg"));
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
    }
}