package com.wuaipojie;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.virtualmodule.VirtualModule;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.util.Map;

public class Camera extends VirtualModule<Void> {

    private static final Logger log = LoggerFactory.getLogger(com.github.unidbg.virtualmodule.android.SystemProperties.class);

    public Camera(Emulator<?> emulator, Void extra) {
        super(emulator, extra, "libcamera2ndk.so");
    }

    @Override
    protected void onInitialize(Emulator<?> emulator, Void extra, Map<String, UnidbgPointer> symbols) {
        boolean is64Bit = emulator.is64Bit();
        SvcMemory svcMemory = emulator.getSvcMemory();
        symbols.put("ACameraManager_create", svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                System.out.println("ACameraManager_create");
                return 9999;
            }
        }));
        symbols.put("ACameraManager_getCameraIdList", svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Number addr = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer res = emulator.getContext().getPointerArg(1);
                UnidbgPointer pointer = emulator.getMemory().malloc(0x8, true).getPointer();
                System.out.printf("%X, %X, %X\n", addr, res.peer, pointer.peer);
                byte[] size = {2};
                pointer.write(size);

                long pointer_addr = pointer.peer;
                byte[] pointer_bytes = new byte[8];
                for (int i = 0; i < 8; i++) {
                    pointer_bytes[i] = (byte) (pointer_addr & 0xFF);
                    pointer_addr >>= 8;
                }
                res.write(pointer_bytes);

                System.out.println("ACameraManager_getCameraIdList");
                return 0;
            }
        }));
        symbols.put("ACameraManager_delete", svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                System.out.println("ACameraManager_delete");
                return 0;
            }
        }));
        symbols.put("start", svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                System.out.println("carmera start ???");
                return 0;
            }
        }));
    }

}
