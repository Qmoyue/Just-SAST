package io.just.sast.analysis.taint;

import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SerializationModelContractTest {

    @Test
    void oisClassifierIsClosedAndNullSafe() {
        assertTrue(SerializationModel.isOisRead("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;"));
        assertTrue(SerializationModel.isOisRead("java/io/ObjectInputStream", "readUnshared", "()Ljava/lang/Object;"));
        assertTrue(SerializationModel.isOisRead("java/io/ObjectInputStream", "readFields", "()Ljava/io/ObjectInputStream$GetField;"));
        assertFalse(SerializationModel.isOisRead("java/io/ObjectInputStream", "writeObject", "()V"));
        assertFalse(SerializationModel.isOisRead(null, null, null));
    }

    @Test
    void conditionalSourceIsSecondDeserializeAndNotAnExternalRoot() {
        Rule.SourceRule source = new Rule.SourceRule("bridge", "deserialize",
                new Rule.CallMatcher(Match.of("app/Codec"), Match.of("decode"), Match.of("(Ljava/lang/Object;)Ljava/lang/Object;")),
                null, List.of(new Rule.TaintedPos.Arg(0)));
        SerializationModel.Boundary boundary = SerializationModel.source(source,
                "app/Codec", "decode", "(Ljava/lang/Object;)Ljava/lang/Object;").orElseThrow();
        assertEquals(SerializationModel.BoundaryKind.SECOND_DESERIALIZE, boundary.kind());
        assertEquals(SerializationModel.Direction.DESERIALIZE, boundary.direction());
        assertFalse(boundary.externalInput());
        assertTrue(boundary.requiresTaintedInput());
        assertTrue(boundary.canonical().startsWith("serialization-v1|SECOND_DESERIALIZE|"));
    }

    @Test
    void unconditionalSerializeSourceAndIndependentMagicEntryRemainDistinct() {
        Rule.SourceRule source = new Rule.SourceRule("encode", "serialize",
                new Rule.CallMatcher(Match.of("app/Codec"), Match.of("encode"), Match.of("()Ljava/lang/Object;")),
                null, List.of());
        SerializationModel.Boundary sourceBoundary = SerializationModel.source(source,
                "app/Codec", "encode", "()Ljava/lang/Object;").orElseThrow();
        assertEquals(SerializationModel.BoundaryKind.FRAMEWORK_SOURCE, sourceBoundary.kind());
        assertEquals(SerializationModel.Direction.SERIALIZE, sourceBoundary.direction());
        assertFalse(sourceBoundary.externalInput());

        Rule.MagicEntryRule callback = new Rule.MagicEntryRule("read-object", "readObject",
                new Rule.MethodMatcher(Match.of("readObject"), Match.of("()V"), true),
                "java/io/Serializable", "deserialize");
        assertTrue(SerializationModel.magicEntry(callback, "app/Bean", "readObject", "()V").isPresent());

        Rule.MagicEntryRule trigger = new Rule.MagicEntryRule("hash", "hashCode",
                new Rule.MethodMatcher(Match.of("hashCode"), Match.of("()I"), false),
                "java/io/Serializable", "deserialize");
        assertTrue(SerializationModel.magicEntry(trigger, "app/Bean", "hashCode", "()I").isEmpty());
    }
}
