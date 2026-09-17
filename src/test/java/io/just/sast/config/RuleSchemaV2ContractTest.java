package io.just.sast.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for the typed v1-to-v2 rule catalog projection. */
class RuleSchemaV2ContractTest {

    @Test
    void defaultCatalogMigratesAllDefaultRulesWithoutDroppingKinds() throws IOException {
        RuleSet legacy = new YamlRuleLoader().load(Files.newInputStream(
                Path.of("src/main/resources/rules/default-rules.yaml")));
        RuleSchemaV2.Catalog catalog = RuleSchemaV2.adapt(legacy);

        int legacyCount = legacy.sinks().size() + legacy.magicEntries().size()
                + legacy.sources().size() + legacy.models().size() + legacy.fragments().size();
        legacyCount += legacy.conditions().size();
        assertTrue(legacyCount >= 200,
                "default catalog must retain the established rule baseline");
        assertEquals(legacyCount, catalog.rules().size(), "v1 rules must not be silently dropped");
        assertEquals(legacyCount,
                catalog.rules().stream().map(RuleSchemaV2.Definition::id).distinct().count());
        assertTrue(catalog.rules().stream().allMatch(rule -> rule.semantics().hasAnyAxis()));
        assertEquals(Set.of("CONDITION-CC3-UNSAFE-SERIALIZATION",
                        "CONDITION-CC4-FUNCTOR-SERIALIZABLE",
                        "CONDITION-BEANUTILS-CLASS-PROPERTY",
                        "CONDITION-SERIALIZATION-PACKAGE-ALLOWLIST",
                        "CONDITION-OFBIZ-RMI-CLASS-BLOCK"),
                catalog.rules().stream()
                        .filter(rule -> rule.kind() == RuleSchemaV2.RuleKind.CONDITION)
                        .map(RuleSchemaV2.Definition::id)
                        .collect(java.util.stream.Collectors.toSet()));
        assertEquals(catalog.toCanonicalJson(), RuleSchemaV2.adapt(legacy).toCanonicalJson());
        assertEquals(64, catalog.digest().length());

        RuleSchemaV2.Definition classLoader = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-CLASSLOAD-FORNAME".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(classLoader.semantics().capability().contains(RuleSchemaV2.Capability.CLASS_LOADING));
        assertTrue(classLoader.semantics().boundary().contains(RuleSchemaV2.Boundary.CAPABILITY));
        assertTrue(classLoader.semantics().terminal().isEmpty(),
                "capability rules must not masquerade as terminal effects");

        RuleSchemaV2.Definition kryo = catalog.rules().stream()
                .filter(rule -> "JUST-SOURCE-KRYO".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(kryo.semantics().bridge().contains(RuleSchemaV2.Bridge.DESERIALIZE));
        assertTrue(kryo.semantics().source().contains(RuleSchemaV2.Source.DESERIALIZATION));
        assertTrue(kryo.semantics().filter().contains(RuleSchemaV2.Filter.SAFE_CONFIG));

        RuleSchemaV2.Definition callback = catalog.rules().stream()
                .filter(rule -> "JUST-ENTRY-READOBJECT".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(callback.semantics().callback().contains(RuleSchemaV2.Callback.READ_OBJECT));
    }

    @Test
    void legacyCapabilityBoundariesRemainBridgesAndDoNotStopTheChain() throws IOException {
        RuleSet legacy = new YamlRuleLoader().load(Files.newInputStream(
                Path.of("src/main/resources/rules/default-rules.yaml")));
        RuleSchemaV2.Catalog catalog = RuleSchemaV2.adapt(legacy);

        RuleSchemaV2.Definition lookup = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-JNDI-LOOKUP".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(lookup.semantics().capability().contains(RuleSchemaV2.Capability.JNDI));
        assertTrue(lookup.semantics().bridge().contains(RuleSchemaV2.Bridge.JNDI_RMI));
        assertTrue(lookup.semantics().boundary().contains(RuleSchemaV2.Boundary.LOOKUP));
        assertTrue(lookup.semantics().terminal().isEmpty(),
                "lookup is a bridge/capability and static solving must continue to the suffix");
        Rule.SinkRule lookupRule = legacy.sinks().stream()
                .filter(rule -> "JUST-SINK-JNDI-LOOKUP".equals(rule.id()))
                .findFirst().orElseThrow();
        assertEquals(Rule.SinkRole.CAPABILITY, lookupRule.role());
        assertEquals(Rule.SinkRole.CAPABILITY, RuleSchemaV2.sinkRoleFor(lookupRule));

        RuleSchemaV2.Definition ctor = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-PROCESSBUILDER-CTOR".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(ctor.semantics().capability().contains(RuleSchemaV2.Capability.PROCESS));
        assertTrue(ctor.semantics().terminal().isEmpty(),
                "ProcessBuilder construction is not ProcessBuilder.start");

        RuleSchemaV2.Definition start = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-COMMAND-EXEC-PROCESSBUILDER".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(start.semantics().terminal().contains(RuleSchemaV2.Terminal.COMMAND_EXEC));

        RuleSchemaV2.Definition defineClass = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-CLASSLOADER-DEFINECLASS".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(defineClass.semantics().terminal().contains(RuleSchemaV2.Terminal.CLASS_DEFINITION),
                defineClass.semantics().toString());

        RuleSchemaV2.Definition fileRead = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-FILEREAD-FILES".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(fileRead.semantics().terminal().contains(RuleSchemaV2.Terminal.FILE_READ));

        RuleSchemaV2.Definition jdbc = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-JDBC-DRIVERMANAGER".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(jdbc.semantics().capability().contains(RuleSchemaV2.Capability.JDBC));
        assertTrue(jdbc.semantics().bridge().contains(RuleSchemaV2.Bridge.JDBC_DRIVER));
        assertTrue(jdbc.semantics().terminal().isEmpty());

        RuleSchemaV2.Definition jdbcXml = catalog.rules().stream()
                .filter(rule -> "FRAG-JDBC-SPRING-XML-CLASS-DEFINITION".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(jdbcXml.semantics().bridge().contains(RuleSchemaV2.Bridge.JDBC_DRIVER));
        assertTrue(jdbcXml.semantics().bridge().contains(RuleSchemaV2.Bridge.CONFIGURATION));
        assertTrue(jdbcXml.semantics().boundary().contains(RuleSchemaV2.Boundary.CONFIGURATION));
        assertTrue(jdbcXml.semantics().terminal().contains(
                RuleSchemaV2.Terminal.CLASS_DEFINITION));

        RuleSchemaV2.Definition http = catalog.rules().stream()
                .filter(rule -> "JUST-SINK-SSRF-HTTPURLCONNECT".equals(rule.id()))
                .findFirst().orElseThrow();
        assertTrue(http.semantics().terminal().contains(RuleSchemaV2.Terminal.NETWORK_SEND));
        assertTrue(http.semantics().bridge().isEmpty(),
                "ordinary HTTP connect is not a JDBC or JNDI response bridge");
    }

    @Test
    void exactInitialContextLookupCannotLeakLegacyTerminalRole() {
        String descriptor = "(Ljava/lang/String;)Ljava/lang/Object;";
        Rule.SinkRule lookup = new Rule.SinkRule("initial-context-lookup", "JNDI", "HIGH",
                new Rule.CallMatcher(Match.of("javax/naming/InitialContext"),
                        Match.of("lookup"), Match.of(descriptor)),
                List.of(new Rule.TaintedPos.Arg(0)));

        assertEquals(Rule.SinkRole.TERMINAL, lookup.role(),
                "the compatibility constructor still exposes the legacy raw bit");
        assertEquals(Rule.SinkRole.CAPABILITY, RuleSchemaV2.sinkRoleFor(lookup));
        RuleSchemaV2.Definition definition = RuleSchemaV2.adapt(lookup);
        assertTrue(definition.semantics().capability().contains(RuleSchemaV2.Capability.JNDI));
        assertTrue(definition.semantics().bridge().contains(RuleSchemaV2.Bridge.JNDI_RMI));
        assertTrue(definition.semantics().boundary().contains(RuleSchemaV2.Boundary.LOOKUP));
        assertTrue(definition.semantics().terminal().isEmpty());
    }

    @Test
    void malformedTypedDefinitionsFailClosedAndMagicDirectionIsNotAnApplicationEntry()
            throws IOException {
        assertThrows(IllegalArgumentException.class,
                () -> new RuleSchemaV2.Catalog("JUST-RULES-D001-V1", List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new RuleSchemaV2.Definition("bad id", RuleSchemaV2.RuleKind.MODEL,
                        "", "", new RuleSchemaV2.Semantics(Set.of(), Set.of(), Set.of(),
                        Set.of(), Set.of(), Set.of(), Set.of())));

        Rule.MethodMatcher method = new Rule.MethodMatcher(Match.of("writeObject"), null, true);
        Rule.MagicEntryRule write = new Rule.MagicEntryRule("WRITE", "writeObject", method,
                "java/io/Serializable", "serialize");
        RuleSchemaV2.Definition definition = RuleSchemaV2.adapt(write);
        assertTrue(definition.semantics().boundary().contains(RuleSchemaV2.Boundary.UNKNOWN));
        assertTrue(definition.semantics().callback().contains(RuleSchemaV2.Callback.WRITE_OBJECT));
        assertFalse(definition.semantics().boundary().contains(RuleSchemaV2.Boundary.APPLICATION_ENTRY));
    }

    @Test
    void schemaDeclaresAllSemanticAxesAndRejectsDuplicateDefinitions() throws IOException {
        String schema = Files.readString(Path.of("docs/schemas/rules-v2.schema.json"));
        assertTrue(schema.contains("JUST-RULES-D002-V2"));
        for (String axis : List.of("capability", "bridge", "boundary", "terminal", "source",
                "filter", "callback")) {
            assertTrue(schema.contains("\"" + axis + "\""), "missing schema axis " + axis);
        }
        assertTrue(schema.contains("\"additionalProperties\": false"));

        Rule.CallMatcher call = new Rule.CallMatcher(Match.of("a/B"), Match.of("run"), null);
        Rule.SinkRule one = new Rule.SinkRule("DUP", "CODE_EXEC", "HIGH", call,
                List.of(new Rule.TaintedPos.Arg(0)));
        Rule.SinkRule two = new Rule.SinkRule("DUP", "CODE_EXEC", "HIGH", call,
                List.of(new Rule.TaintedPos.Arg(0)));
        assertThrows(IllegalArgumentException.class,
                () -> RuleSchemaV2.adapt(new RuleSet(List.of(one, two), List.of(), List.of(), List.of(), List.of())));
    }

    @Test
    void catalogAndSemanticCollectionsAreImmutable() throws IOException {
        RuleSet legacy = new YamlRuleLoader().load(Files.newInputStream(
                Path.of("src/main/resources/rules/default-rules.yaml")));
        RuleSchemaV2.Catalog catalog = RuleSchemaV2.adapt(legacy);
        assertThrows(UnsupportedOperationException.class,
                () -> catalog.rules().add(catalog.rules().get(0)));
        assertThrows(UnsupportedOperationException.class,
                () -> catalog.rules().get(0).semantics().callback().clear());
        assertFalse(catalog.toCanonicalJson().contains("\r"));
    }
}
