package io.just.sast.verify.boot;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

/** Java 8 child-side native proof for the Windows AppContainer token. */
public final class WindowsProcessAttestation {
    private static final int TOKEN_QUERY = 0x0008;
    private static final int TOKEN_INTEGRITY_LEVEL = 25;
    private static final int TOKEN_IS_APPCONTAINER = 29;
    private static final int LOW_INTEGRITY_RID = 0x1000;

    private WindowsProcessAttestation() { }

    public static boolean appContainerLow() {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return false;
        Pointer token = null;
        try {
            TokenApi api = Native.load("advapi32", TokenApi.class);
            KernelApi kernel = Native.load("kernel32", KernelApi.class);
            PointerByReference tokenRef = new PointerByReference();
            if (!api.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, tokenRef)) return false;
            token = tokenRef.getValue();
            Memory appContainer = new Memory(4);
            IntByReference returned = new IntByReference();
            if (!api.GetTokenInformation(token, TOKEN_IS_APPCONTAINER, appContainer,
                    (int) appContainer.size(), returned) || appContainer.getInt(0) == 0) return false;
            returned.setValue(0);
            api.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, null, 0, returned);
            int size = returned.getValue();
            if (size <= 0 || size > 4096) return false;
            Memory label = new Memory(size);
            if (!api.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, label, size, returned)) return false;
            Pointer sid = label.getPointer(0);
            if (sid == null || Pointer.nativeValue(sid) == 0L) return false;
            Pointer count = api.GetSidSubAuthorityCount(sid);
            if (count == null) return false;
            int subAuthorities = count.getByte(0) & 0xff;
            if (subAuthorities == 0 || subAuthorities > 15) return false;
            Pointer last = api.GetSidSubAuthority(sid, subAuthorities - 1);
            return last != null && last.getInt(0) == LOW_INTEGRITY_RID;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (token != null) {
                try { Native.load("kernel32", KernelApi.class).CloseHandle(token); }
                catch (Throwable ignored) { }
            }
        }
    }

    private interface TokenApi extends StdCallLibrary {
        boolean OpenProcessToken(Pointer process, int desiredAccess, PointerByReference token);
        boolean GetTokenInformation(Pointer token, int informationClass, Pointer information,
                                    int informationLength, IntByReference returnLength);
        Pointer GetSidSubAuthorityCount(Pointer sid);
        Pointer GetSidSubAuthority(Pointer sid, int index);
    }
    private interface KernelApi extends StdCallLibrary {
        Pointer GetCurrentProcess();
        boolean CloseHandle(Pointer handle);
    }
}
