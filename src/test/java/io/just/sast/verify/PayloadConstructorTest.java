package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import java.io.Serializable;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 构造可行性只是验证器能力边界：共享字段类型与不可检查子图必须正确向上归因。 */
class PayloadConstructorTest {

    private abstract static class UninstantiableChild implements Serializable { }

    private static final class HasUnfillableField implements Serializable {
        private UninstantiableChild child;
    }

    @Test
    void childSkipDoesNotBecomeConstructibleParent() {
        PayloadConstructor constructor = new PayloadConstructor(getClass().getClassLoader());
        PayloadConstructor.ConstructionResult result =
                constructor.tryConstruct(HasUnfillableField.class.getName());
        assertEquals("PARTIALLY_CONSTRUCTIBLE", result.verdict(), result.detail());
    }

    @Test
    void linkageFailureIsScopedToCapabilityCheck() {
        String missing = "missing.optional.Dependency";
        ClassLoader loader = new ClassLoader(getClass().getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.equals(missing)) {
                    throw new NoClassDefFoundError(name);
                }
                return super.loadClass(name, resolve);
            }
        };
        PayloadConstructor constructor = new PayloadConstructor(loader);
        PayloadConstructor.ConstructionResult result = constructor.tryConstruct(missing);
        assertEquals("SKIP", result.verdict(), result.detail());
    }
}
