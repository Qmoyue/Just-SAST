package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

/** Owns the stable chain identity shared by reports and report consumers. */
public final class ChainIdentity {

    private ChainIdentity() {
    }

    public static String of(Chain chain) {
        if (chain == null) {
            throw new IllegalArgumentException("chain is required");
        }
        return of(chain.ruleId(), chain.entryClass(), chain.entryMethod(), entryDescriptor(chain),
                chain.entryKind(), chain.sinkClass(), chain.sinkMethod(), sinkDescriptor(chain));
    }

    public static String of(String ruleId, String entryClass, String entryMethod,
                            String entryDescriptor, String entryKind, String sinkClass,
                            String sinkMethod, String sinkDescriptor) {
        return String.join("|", safe(ruleId), safe(entryClass), safe(entryMethod),
                safe(entryDescriptor), safe(entryKind), safe(sinkClass), safe(sinkMethod),
                safe(sinkDescriptor));
    }

    public static String entryDescriptor(Chain chain) {
        if (chain != null && chain.hops() != null) {
            for (ChainHop hop : chain.hops()) {
                if (hop != null && hop.kind() == HopKind.ENTRY && !safe(hop.desc()).isBlank()) {
                    return hop.desc();
                }
            }
        }
        return "";
    }

    public static String sinkDescriptor(Chain chain) {
        if (chain == null) {
            return "";
        }
        if (!safe(chain.sinkDescriptor()).isBlank()) {
            return chain.sinkDescriptor();
        }
        if (chain.hops() != null) {
            for (ChainHop hop : chain.hops()) {
                if (hop != null && safe(chain.sinkClass()).equals(safe(hop.toOwner()))
                        && safe(chain.sinkMethod()).equals(safe(hop.toName()))
                        && !safe(hop.desc()).isBlank()) {
                    return hop.desc();
                }
            }
        }
        return "";
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
