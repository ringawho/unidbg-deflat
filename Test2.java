package com.wuaipojie;

import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
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
import unicorn.Arm64Const;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;

public class Test2 {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final JSONObject cmdMap = getCmdMap();
    private final JSONObject condBranchMap = new JSONObject();
    private final JSONObject branchLinkMap = new JSONObject();
    private int[] regIDs = ARM.getAll64Registers();
    private List<Instruction> accessedInstructions = new ArrayList<>();

    private final Stack<State> states = new Stack<>();
    static class State {
        Instruction ins;
        Number[] regsValue;

        public State(Instruction ins, Number[] regsValue) {
            this.ins = ins;
            this.regsValue = regsValue;
        }
    }

    static class CondInfo {
        long condAddress;
        boolean isCondSuc;
    }

    public Test2() {
        this.emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.lib52pojie.so.crackme2024")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        Memory memory = setupMemory();

        new Camera(emulator, null).register(memory);

        vm = emulator.createDalvikVM();
        vm.setVerbose(true);

        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/wuaipojie/lib52pojie.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        emulator.getBackend().hook_add_new(new CodeHook() {
            Instruction last = null;
            CondInfo condInfo = new CondInfo();
            long[] stackCheckFailedAddr = {
                    0x00016874, 0x00018120, 0x0001ae1c, 0x0001b54c, 0x0001cf38,
                    0x0001e858, 0x0002101c, 0x000227c4, 0x00022e48, 0x00025ed4,
                    0x00027224, 0x00028794, 0x000290cc, 0x0002a264, 0x0002a5c4,
                    0x0002ab30, 0x0002afe4, 0x0002e27c, 0x0002facc, 0x00031ee8,
                    0x00036bb4, 0x0003c658, 0x0003d668, 0x0003d800, 0x0003fb60,
                    0x00041040
            };
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long offset = address - module.base;
                Instruction ins = emulator.disassemble(address, size, 0)[0];
                try {

                System.out.println(Long.toHexString(address) + " " + ins);
                if (offset == 0x1c7ac) {
//                    emulator.showRegs();
//                    emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X15, 0xbffff520);
//                    emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X8, 0xbffff710);
                }

                last = ins;

                short[] read = ins.regsAccess().getRegsRead();
                if (ins.getMnemonic().equals("br")) {
                    if (!cmdMap.containsKey(offset)) {
                        throw new RuntimeException("Unexpected br!");
                    } else if (cmdMap.getLongValue(String.valueOf(offset)) != condInfo.condAddress) {
                        throw new RuntimeException("Unexpected br cond address!");
                    }
                    OpInfo opInfo = (OpInfo) ins.getOperands();
                    Operand operand = opInfo.getOperands()[0];
                    assert operand.getType() == Arm64_const.ARM64_OP_REG;
                    int reg = ins.mapToUnicornReg(operand.getValue().getReg());
                    long branchAddr = backend.reg_read(reg).longValue();

                    JSONObject temp = condBranchMap.containsKey(String.valueOf(offset))
                            ? (JSONObject) condBranchMap.get(String.valueOf(offset))
                            : new JSONObject();
                    temp.put("cond", condInfo.condAddress);
                    temp.put(condInfo.isCondSuc ? "true" : "false", branchAddr - module.base);
                    condBranchMap.put(String.valueOf(offset), temp);
                }

                if (hasNZCV(ins, read)) {
                    if (!states.empty() && states.peek().ins.getAddress() == address) {
                        states.pop();
                    } else if (!isHitAddress(accessedInstructions, ins)) {
                        Number[] regsValue = new Number[regIDs.length];
                        for (int i = 0; i < regIDs.length; i++) {
                            regsValue[i] = backend.reg_read(regIDs[i]);
                        }
                        states.push(new State(ins, regsValue));

                        String cond = getCond(ins);
                        Cpsr cpsr = Cpsr.getArm64(backend);
                        boolean condSuc = isCondSuc(cond, cpsr);
                        toggleCpsrStatus(cond, cpsr, condSuc);
                    }
                    condInfo.condAddress = offset;
                    condInfo.isCondSuc = isCondSuc(getCond(ins), Cpsr.getArm64(backend));
                    System.out.println(String.format("%X cond: %s", address, condInfo.isCondSuc));
                }
//                System.out.println(Arrays.stream(stackCheckFailedAddr).anyMatch(addr -> addr == offset));
                if ((isHitAddress(accessedInstructions, ins) ||
                        Arrays.stream(stackCheckFailedAddr).anyMatch(addr -> addr == offset) ||
                        offset == module.base + 0x1cf34) &&
                        !states.empty()) {
                    State state = states.peek();
                    for (int i = 0; i < regIDs.length; i++) {
                        backend.reg_write(regIDs[i], state.regsValue[i]);
                    }
                    last = null;


                    for (int i = 0; i < accessedInstructions.size(); i++) {
                        if (accessedInstructions.get(i).getAddress() == address) {
                            accessedInstructions.subList(i, accessedInstructions.size()).clear();
                            break;
                        }
                    }
                } else {
                    accessedInstructions.add(ins);
                }

                } catch (Exception e) {
                    System.err.println(String.format("ERROR: %X %s %s", address, ins, e.getMessage()));
//                    e.printStackTrace();
                }
//                System.out.println(String.format("%X", address));
            }

            @Override
            public void onAttach(UnHook unHook) {}

            @Override
            public void detach() {}
        }, module.base + 0x1befc, module.base + 0x1cf38, null);
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
//                    return "stopped";
                    return "running";
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
        String[] opList = ins.toString().split(" ");
        if (ins.toString().startsWith("cbz")) {
            return "eq";
        } else if (ins.toString().startsWith("cbnz")) {
            return "ne";
        } else if (ins.toString().startsWith("b.")) {
            return opList[0].split("\\.")[1];
        }
        return opList[opList.length - 1];
    }

    private boolean hasNZCV(Instruction ins, short[] regs) {
        for (short r : regs) {
            if (ins.mapToUnicornReg(r) == Arm64Const.UC_ARM64_REG_NZCV) {
                return true;
            }
        }
        return false;
    }

    private boolean isHitAddress(List<Instruction> list, Instruction ins) {
        for (Instruction i : list) {
            if (ins.getAddress() == i.getAddress()) {
                return true;
            }
        }
        return false;
    }

    public static boolean jsonContainsValue(JSONObject jsonObject, long value) {
        for (String key : jsonObject.keySet()) {
            if (jsonObject.getLong(key).equals(value)) {
                return true;
            }
        }
        return false;
    }

    // https://developer.arm.com/documentation/dui0801/l/Condition-Codes/Condition-code-suffixes-and-related-flags?lang=en
    private boolean isCondSuc(String cond, Cpsr cpsr) {
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
            case "al": return true;
        }
        throw new RuntimeException("unknown cond");
    }

    private void toggleCpsrStatus(String cond, Cpsr cpsr, boolean condSuc) {
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
            case "al":
            default:
                throw new RuntimeException("unknown cond");
        }
    }


    public static void main(String[] args) {
        // 创建一个 DateTimeFormatter 对象，用于格式化日期时间
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

        // 使用 DateTimeFormatter 对象将 LocalDateTime 对象格式化为字符串，并打印输出
        System.out.println("start time: " + LocalDateTime.now().format(formatter));
        Test2 test = new Test2();
        try {
            test.checkSn();
            test.destory();
        } catch (Exception e) {
//            test.emulator.showRegs();
            e.printStackTrace();
        }
        System.out.println(test.condBranchMap.toJSONString());
        System.out.println(test.branchLinkMap.toJSONString());
        System.out.println("end time: " + LocalDateTime.now().format(formatter));
    }
}