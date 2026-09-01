package io.just.sast.blackboard;

/**
 * Typed extension fact exchanged through the blackboard.
 *
 * <p>Implementations are required to be immutable records.  The marker keeps the public
 * channel closed to arbitrary mutable event payloads while remaining extensible for plugins;
 * {@link Blackboard} enforces the record requirement at publication time.</p>
 */
public interface BlackboardFact {
}
