package io.just.sast.model;

/** try-catch 块：[start, end) 内的指令异常时跳转到 handler。type 为 null 表示 catch-all。 */
public record TryCatchFact(int start, int end, int handler, String type) {}
