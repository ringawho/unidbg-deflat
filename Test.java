package com.wuaipojie;

import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.linux.android.*;
import com.github.unidbg.linux.android.dvm.Array;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.virtualmodule.VirtualModule;
import unicorn.Arm64Const;

import java.io.*;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Test {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final JSONObject cmdMap = getCmdMap();
    private final JSONObject condBranchMap = new JSONObject();
    private final JSONObject branchLinkMap = new JSONObject();

    public Test() {
        this.emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.lib52pojie.so.crackme2024")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
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

        new Camera(emulator, null).register(memory);
        emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
            @Override
            public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
                if (pathname.equals("/data/app/com.wuaipojie.crackme2024/base.apk")) {
                    System.out.println("read base.apk");
                    File file = new File("/home/ring/reverse_workspace/Happy_New_Year_2024_Challenge/problem4/problem4.apk");
                    return FileResult.success(new SimpleFileIO(oflags, file, pathname));
                }
                return null;
            }
        });

        vm = emulator.createDalvikVM();
        vm.setVerbose(true);

        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/wuaipojie/lib52pojie.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        Set<Long> branchSet = new HashSet<>();
        Map<Long, Integer> condBranchMap = new HashMap<>();
        int[] regIds = ARM.getAll64Registers();
        Number[] regsValue = new Number[regIds.length];
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                try {
                long offset = address - module.base;
                Instruction[] ins = emulator.disassemble(address, size, 0);
                // 直接替代检测2的结果
//                if (offset == 0x1ce58) {
//                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
//                    System.out.println(backend.reg_read(Arm64Const.UC_ARM64_REG_X0));
//                }
//                if (offset == 0x1f488) {
//                    byte[] md5 = { 0x30, 0x50, (byte) 0xc9, 0x11, (byte) 0xe2, (byte) 0x8e, (byte) 0xf3, (byte) 0xee, (byte) 0xc8, 0x47, (byte) 0xf4, 0x13, (byte) 0xdd, 0x3d, 0x15, 0x27 };
//                    long addr = (long) backend.reg_read(Arm64Const.UC_ARM64_REG_X0);
//                    backend.mem_write(addr, md5);
//                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, address + 4);
//                }

                if (ins[0].getMnemonic().equals("blr")) {
                    OpInfo opInfo = (OpInfo) ins[0].getOperands();
                    Operand operand = opInfo.getOperands()[0];
                    assert operand.getType() == Arm64_const.ARM64_OP_REG;
                    if (operand.getType() == Arm64_const.ARM64_OP_REG) {
                        int reg = ins[0].mapToUnicornReg(operand.getValue().getReg());
                        long branchAddr = backend.reg_read(reg).longValue();
                        if (branchSet.contains(branchAddr)) {
                            return;
                        }
                        branchSet.add(branchAddr);
                        Module branchModule = memory.findModuleByAddress(branchAddr);
                        if (branchAddr >= module.base && branchAddr <= module.base + module.size) {
//                            System.out.printf("[%6X] blr %6X\n", offset, branchAddr - module.base);
                            branchLinkMap.put(String.valueOf(offset), branchAddr - module.base);
                        } else if (branchModule != null) {
                            Symbol symbol = branchModule.findClosestSymbolByAddress(branchAddr, true);
                            long symbolAddr = branchModule.findSymbolByName(symbol.toString()) != null ? branchModule.findSymbolByName(symbol.toString()).getAddress() : -1;
                            System.out.printf("[%6X] blr %s\n", offset, symbolAddr == branchAddr ? module.name + " " + symbol.getName() : " can not be trusted! maybe jni function");
                        } else {
                            System.out.printf("[%6X] Not find Module, may be virtual module\n", offset);
                        }
                    }
                } else if ((ins[0].getMnemonic().equals("csel") || ins[0].getMnemonic().equals("cset")) && jsonContainsValue(cmdMap, offset)) {
                    String[] opList = ins[0].getOpStr().split(", ");
                    String cond = opList[opList.length - 1];
                    Cpsr cpsr = Cpsr.getArm64(backend);
                    boolean condSuc = isCondSuc(cond, cpsr);
                    if (!condBranchMap.containsKey(offset)) {
                        for (int i = 0; i < regIds.length; i++) {
                            regsValue[i] = backend.reg_read(regIds[i]);
                        }
                        toggleCpsrStatus(cond, cpsr, condSuc);
                        // 1 代表之前是符合条件的，0代表不符合条件，这里由于toggle，所以要取反
                        condBranchMap.put(offset, condSuc ? 0 : 1);
                    } else if (condBranchMap.get(offset) == 0 || condBranchMap.get(offset) == 1) {
                        // 3代表符合条件，2代表不符合条件
                        // 4代表已经无需再处理
                        condBranchMap.put(offset, condSuc ? 3 : 2);
                    }
                } else if (ins[0].getMnemonic().equals("br") && cmdMap.containsKey(offset)) {
                    long condAddr = cmdMap.getLongValue(String.valueOf(offset));

                    OpInfo opInfo = (OpInfo) ins[0].getOperands();
                    Operand operand = opInfo.getOperands()[0];
                    assert operand.getType() == Arm64_const.ARM64_OP_REG;
                    int reg = ins[0].mapToUnicornReg(operand.getValue().getReg());
                    long branchAddr = backend.reg_read(reg).longValue();
//                    System.out.printf("%X, %X\n", condAddr, branchAddr - module.base);

                    int status = condBranchMap.get(condAddr);
                    if (status == 0 || status == 1) {
                        for (int i = 0; i < regIds.length; i++) {
                            backend.reg_write(regIds[i], regsValue[i]);
                        }
                    } else {
                        condBranchMap.put(condAddr, 4);
                    }
                    if (status < 4) {
                        JSONObject temp = status <= 1 ? new JSONObject() : (JSONObject) Test.this.condBranchMap.get(String.valueOf(offset));
                        temp.put("cond", condAddr);
                        temp.put(status == 1 || status == 3 ? "true" : "false", branchAddr - module.base);
                        Test.this.condBranchMap.put(String.valueOf(offset), temp);
                    }
                } else if (ins[0].getMnemonic().equals("ret")) {
//                    System.out.println("ret");
                }
                } catch (Exception e) {
                    System.out.printf("%X\n", address);
                    e.printStackTrace();
                }
            }

            @Override
            public void onAttach(UnHook unHook) {}

            @Override
            public void detach() {}
//        }, module.base + 0x2a5c8, module.base + 0x2ab2c, null);
//        }, module.base + 0x3da80, module.base + 0x3fb5c, null);
        }, module.base + 0x1befc, module.base + 0x1cf38, null);
//        }, module.base, module.base + module.size, null);
//          }, module.base + 0x3fb64, module.base + 0x3fe84, null);


        HookZz hook = HookZz.getInstance(emulator);
        hook.wrap(module.base + 0x1e924, new WrapCallback<RegisterContext>() {
            long x0 = 0;
            @Override
            public void preCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
                System.out.printf("%x: ", ctx.getLR());
                x0 = ctx.getLongArg(0);
            }

            @Override
            public void postCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
//                byte[] a = emulator.getBackend().mem_read(x0, 0x50);
//                byte[] a = emulator.getBackend().mem_read(ctx.getLongArg(0), 0x50);
//                int index = 0;
//                for (int i = 0; i < a.length; i++) {
//                    if (a[i] == 0) {
//                        System.out.println("string: " + new String(a, 0, i));
//                        break;
//                    }
//                }
//                System.out.println("all: " + new String(a));
                System.out.println(ctx.getLongArg(0));
                super.postCall(emulator, ctx, info);
            }
        });



//        emulator.traceCode(module.base + 0x17bb4, module.base + 0x17bb4);
//        emulator.attach().addBreakPoint(module.base + 0x17fb4, (emulator, address) -> {
////            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, 1);
//            System.out.println("0x17fb4 " + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0));
////                emulator.showRegs(Arm64Const.UC_ARM64_REG_X0);
//            return true;
////                return false;
//        });
//        emulator.attach().addBreakPoint(module.base + 0x175c4, (emulator, address) -> {
////            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, 1);
//            System.out.println("0x175c4 " + emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0));
////            emulator.showRegs(Arm64Const.UC_ARM64_REG_X0);
//            return true;
//        });
//        emulator.attach().addBreakPoint(module.base + 0x3dee4, (emulator1, address) -> {
//            emulator.showRegs();
//            return true;
//        });
//        try {
////            emulator.traceCode(module.base, module.base + module.size);
////                    .setRedirect(new PrintStream("52pojie.log"));
//            emulator.traceCode(module.base + 0x1e924, module.base + 0x21018).setRedirect(new PrintStream("52pojie.log"));  // max module.size
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        }
    }

    private Number x0;

    private void hook() {
//        21020 cmp str or arr ???
//        1e24c check adb ??
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

    private void stringFromJNI() {
        DvmObject<?> dvmObject = vm.resolveClass("com/ring/testjni/MainActivity").newObject(null);
        String result = dvmObject.callJniMethodObject(emulator, "stringFromJNI()Ljava/lang.String;").toString();
        System.out.println(result);
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
        try {
            // 创建一个 DateTimeFormatter 对象，用于格式化日期时间
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

            // 使用 DateTimeFormatter 对象将 LocalDateTime 对象格式化为字符串，并打印输出
            System.out.println("start time: " + LocalDateTime.now().format(formatter));
            Test test = new Test();
            test.checkSn();
//            test.stringFromJNI();
            test.destory();
            System.out.println(test.condBranchMap.toJSONString());
            System.out.println(test.branchLinkMap.toJSONString());
            System.out.println("end time: " + LocalDateTime.now().format(formatter));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}