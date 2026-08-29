package io.just.sast.blackboard;

/** 链跳类型。 */
public enum HopKind {
    DIRECT_CALL,
    VIRTUAL_DISPATCH,
    LAMBDA,
    NATIVE_CALLBACK,
    FIELD_FLOW,
    ENTRY
}
