package io.just.sast.analysis.entry;

import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.analysis.taint.SerializationModel;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.HandleRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.TypeRef;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Demand-driven dependency boundary used between the frontend and CPG.
 *
 * <p>The frontend still reads and parses every bounded input entry.  This class only decides
 * which immutable model classes are useful to downstream graph/solver phases.  Keeping those
 * responsibilities separate means an omitted class is visible as a demand-slice policy rather
 * than being confused with an archive parse failure.  Application classes, concrete bytecode
 * references, rule capability owners and declared chain-fragment anchors are retained before a
 * small, deterministic reference closure is followed.  No benchmark name, path or expected
 * chain is consulted.</p>
 */
public final class DemandDrivenProgramSlice {

    /** A deliberately conservative bound for the graph-facing dependency closure. */
    public static final int MAX_SELECTED_CLASSES = 8_192;
    /** Limit recursive dependency expansion; application and capability roots start at depth 0. */
    public static final int MAX_REFERENCE_DEPTH = 4;
    /** Keep dynamic JDBC driver discovery finite without treating a driver jar as a full root. */
    private static final int MAX_JDBC_REFERENCE_DEPTH = 8;
    private static final int MAX_JDBC_DISPATCH_TARGETS = 4;
    private static final String JDBC_DRIVER = "java/sql/Driver";
    private static final String JDBC_CONNECT_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;";
    private static final String JDBC_LOAD_CLASS_DESCRIPTOR =
            "(Ljava/lang/String;)Ljava/lang/Class;";
    private static final String JDBC_CLASS_NEW_INSTANCE_DESCRIPTOR =
            "()Ljava/lang/Object;";

    private DemandDrivenProgramSlice() {
    }

    public record Result(LoadResult load, boolean applied, int inputClasses,
                         int selectedClasses, int inputDependencies, int selectedDependencies,
                         int capabilityClasses, int ruleAnchorClasses, int referenceRounds,
                         boolean capped) {
        public Result {
            load = Objects.requireNonNull(load, "load");
            if (inputClasses < 0 || selectedClasses < 0 || inputDependencies < 0
                    || selectedDependencies < 0 || capabilityClasses < 0
                    || ruleAnchorClasses < 0 || referenceRounds < 0) {
                throw new IllegalArgumentException("slice counters must be non-negative");
            }
        }

        public static Result unchanged(LoadResult load, int inputDependencies) {
            return new Result(load, false, load.classCount(), load.classCount(),
                    Math.max(0, inputDependencies), Math.max(0, inputDependencies),
                    0, 0, 0, false);
        }
    }

    /**
     * Select the graph-facing model for a known application scope.  Unknown/empty scope is a
     * fail-open compatibility path: it returns the original bounded load and never invents an
     * application root.
     */
    public static Result select(LoadResult input, Set<String> applicationClassNames,
                                RuleSet rules) {
        if (input == null) {
            LoadResult empty = new LoadResult(Map.of(), List.of(), 0, 0,
                    List.of("NULL_INPUT"));
            return new Result(empty, false, 0, 0, 0, 0, 0, 0, 0, false);
        }
        Map<String, ClassInfo> available = input.classes();
        int inputDependencies = dependencyCount(available, applicationClassNames);
        if (available.isEmpty() || applicationClassNames == null
                || applicationClassNames.isEmpty()) {
            return Result.unchanged(input, inputDependencies);
        }

        Set<String> application = new TreeSet<>();
        for (String name : applicationClassNames) {
            if (name != null && available.containsKey(name)) {
                application.add(name);
            }
        }
        if (application.isEmpty()) {
            return Result.unchanged(input, inputDependencies);
        }

        RuleSet ruleSet = rules == null ? RuleSet.EMPTY : rules;
        Set<String> anchors = ruleAnchors(ruleSet, available);
        Set<String> directApplicationReferences = directReferences(application, available);
        Set<String> capability = capabilityClasses(available, ruleSet, anchors,
                application, directApplicationReferences);

        // A callback or fragment anchor is a useful demand hint only after the application
        // itself exposes a boundary that can supply/deserialize a value.  Previously every
        // strong readObject callback and every literal fragment owner was made a root, which
        // turned a dependency-only gadget kernel into the default graph.  Keep the class-level
        // pre-CPG slice conservative: graph-level ApplicationEntryIndex performs the complete
        // typed entry/site/terminal join later, while this stage admits only candidates that
        // are both boundary-backed and class-level relevant to a configured terminal.
        boolean applicationBoundary = hasApplicationBoundary(application, available, ruleSet);
        Set<String> terminalRelevant = terminalRelevantClasses(available, ruleSet);
        // A declarative fragment is a semantic edge, not an ordinary bytecode call path.
        // Its callback entry (for example EventListenerList.toString) may have no reference
        // to the eventual terminal owner at all; filtering it through the reverse literal
        // terminal slice therefore drops a valid dependency suffix before FragmentKnowledgeSource
        // can materialize the typed fragment.  Admit only complete fragment anchor sets and
        // only after an application execution boundary exists.  This is intentionally a
        // bounded data-driven exception: it never creates an application root or a finding by
        // itself, and unanchored gadget kernels still remain outside the default graph.
        Set<String> fragmentAnchors = applicationBoundary
                ? completeFragmentAnchorClasses(ruleSet, available)
                : Set.of();
        Set<String> connectedAnchors = applicationBoundary
                ? anchors.stream().filter(terminalRelevant::contains).collect(java.util.stream.Collectors.toCollection(TreeSet::new))
                : Set.of();
        Set<String> connectedCapability = applicationBoundary
                ? capability.stream().filter(terminalRelevant::contains).collect(java.util.stream.Collectors.toCollection(TreeSet::new))
                : Set.of();
        // A secondary deserializer is often hidden behind a framework conversion interface:
        // the application calls Converter.convert(Object), while the concrete BeanConverter
        // implementation invokes ObjectUtil/SerializationUtils.deserialize.  That edge is a
        // semantic dispatch fact and therefore cannot be recovered from the application's exact
        // MethodRef closure alone.  Retain the concrete source-host classes (and, below, the
        // methods that contain the source call) only after an application boundary exists.  This
        // is a rule-driven bridge admission, not a package or benchmark allow-list.
        Set<String> sourceBridgeHosts = applicationBoundary
                ? sourceBridgeHostClasses(available, ruleSet)
                : Set.of();
        // URLClassLoader/Class.newInstance followed by Driver.connect is a bounded dynamic
        // selection boundary.  The class name is still a runtime value, so the scanner must not
        // choose one driver by name; it retains only concrete implementations of java.sql.Driver
        // from the explicitly loaded input artifacts and follows their bytecode call closure.
        Set<String> jdbcDriverClasses = applicationBoundary
                ? jdbcDriverImplementationClasses(available, application)
                : Set.of();

        // Application classes remain roots so the application artifact is represented in the
        // graph.  Dependency callback/fragment classes are never independent roots: they must
        // pass the boundary + terminal relevance gate above or be reached by application code.
        Map<String, Integer> selectedDepth = new LinkedHashMap<>();
        boolean capped = false;
        int rounds = 0;
        // First compute the application-owned reference closure at method granularity.  The
        // former class-granularity walk expanded every method of each dependency class, so a
        // single ObjectMapper/readValue call pulled in an entire framework.  Following only
        // methods reachable from an application boundary preserves bridge/callback edges while
        // avoiding unrelated overloads and utility subgraphs.
        for (String root : application) {
            if (available.containsKey(root)) {
                selectedDepth.putIfAbsent(root, 0);
            }
        }
        MethodSelection applicationSelection = applicationMethodClosure(application, available,
                ruleSet);
        Map<String, Integer> methodClasses = applicationSelection.classDepth();
        Map<String, Set<String>> selectedMethods = new TreeMap<>();
        mergeMethodSelection(selectedMethods, applicationSelection.methods());
        for (Map.Entry<String, Integer> entry : methodClasses.entrySet()) {
            if (selectedDepth.size() >= MAX_SELECTED_CLASSES
                    && !selectedDepth.containsKey(entry.getKey())) {
                capped = true;
                break;
            }
            selectedDepth.merge(entry.getKey(), entry.getValue(), Math::min);
            rounds = Math.max(rounds, entry.getValue() + 1);
        }
        JustLogger.debug("需求切片边界：applicationBoundary={} terminalRelevantClasses={} "
                        + "connectedAnchors={} connectedCapability={} fragmentAnchors={} methodClosure={} selected={}",
                applicationBoundary, terminalRelevant.size(), connectedAnchors.size(),
                connectedCapability.size(), fragmentAnchors.size(), methodClasses.size(), selectedDepth.size());

        // Then expand only the suffix of connected callback/fragment candidates.  This uses the
        // same method-level terminal filter as the application closure.  A class-level reverse
        // reference slice is too coarse for framework libraries: nearly every utility class
        // mentions a common terminal type in a descriptor and would recreate the full graph.
        Set<String> suffixRoots = new TreeSet<>();
        suffixRoots.addAll(connectedAnchors);
        suffixRoots.addAll(connectedCapability);
        suffixRoots.addAll(sourceBridgeHosts);
        // Keep every class named by a complete semantic fragment.  The fragment source will
        // still require all anchors and a terminal rule at composition time; retaining these
        // classes here merely preserves the immutable facts needed to prove that relation.
        for (String fragmentAnchor : fragmentAnchors) {
            if (selectedDepth.size() >= MAX_SELECTED_CLASSES
                    && !selectedDepth.containsKey(fragmentAnchor)) {
                capped = true;
                break;
            }
            selectedDepth.putIfAbsent(fragmentAnchor, 0);
        }
        MethodSelection suffixSelection = suffixMethodClosure(suffixRoots, available,
                ruleSet);
        mergeMethodSelection(selectedMethods, suffixSelection.methods());
        Map<String, Integer> suffixClasses = suffixSelection.classDepth();
        for (Map.Entry<String, Integer> entry : suffixClasses.entrySet()) {
            if (selectedDepth.size() >= MAX_SELECTED_CLASSES
                    && !selectedDepth.containsKey(entry.getKey())) {
                capped = true;
                break;
            }
            selectedDepth.merge(entry.getKey(), entry.getValue(), Math::min);
            rounds = Math.max(rounds, entry.getValue() + 1);
        }
        MethodSelection jdbcDriverSelection = jdbcDriverMethodClosure(jdbcDriverClasses,
                available);
        mergeMethodSelection(selectedMethods, jdbcDriverSelection.methods());
        for (Map.Entry<String, Integer> entry : jdbcDriverSelection.classDepth().entrySet()) {
            if (selectedDepth.size() >= MAX_SELECTED_CLASSES
                    && !selectedDepth.containsKey(entry.getKey())) {
                capped = true;
                break;
            }
            selectedDepth.merge(entry.getKey(), entry.getValue(), Math::min);
            rounds = Math.max(rounds, entry.getValue() + 1);
        }

        // Preserve the frontend's deterministic insertion order.  Sorting the selection itself
        // would change method/node IDs for old consumers even though the semantic set is equal.
        Map<String, ClassInfo> selected = new LinkedHashMap<>();
        Set<String> retainAllMethods = new HashSet<>(application);
        retainAllMethods.addAll(fragmentAnchors);
        for (Map.Entry<String, ClassInfo> entry : available.entrySet()) {
            if (selectedDepth.containsKey(entry.getKey())) {
                ClassInfo info = entry.getValue();
                if (retainAllMethods.contains(entry.getKey())) {
                    selected.put(entry.getKey(), info);
                    continue;
                }
                Set<String> wanted = selectedMethods.getOrDefault(entry.getKey(), Set.of());
                List<MethodInfo> methods = info.methods().stream()
                        .filter(method -> retainMethod(method, wanted, ruleSet))
                        .toList();
                // Keeping a class with no selected body is still useful for type/field
                // resolution, but an empty method list must be visible as a partial demand
                // slice rather than silently looking like a complete class model.
                if (methods.size() != info.methods().size()) {
                    selected.put(entry.getKey(), new ClassInfo(info.internalName(),
                            info.superName(), info.interfaces(), info.access(), methods,
                            info.fields(), info.annotationDescriptors()));
                } else {
                    selected.put(entry.getKey(), info);
                }
            }
        }
        boolean methodsPruned = selected.values().stream().anyMatch(info ->
                available.get(info.internalName()) != info
                        && info.methods().size() < available.get(info.internalName()).methods().size());
        if (selected.size() >= available.size() && !capped && !methodsPruned) {
            return new Result(input, false, available.size(), available.size(),
                    inputDependencies, inputDependencies, capability.size(), anchors.size(),
                    rounds, false);
        }

        LinkedHashSet<String> reasons = new LinkedHashSet<>(input.completenessReasons());
        reasons.add("DEPENDENCY_DEMAND_SLICE_APPLIED");
        if (!jdbcDriverClasses.isEmpty()) {
            reasons.add("JDBC_DRIVER_IMPLEMENTATIONS_SELECTED:" + jdbcDriverClasses.size());
        }
        if (methodsPruned) {
            reasons.add("DEPENDENCY_METHOD_DEMAND_SLICE_APPLIED");
        }
        if (capped) {
            reasons.add("DEPENDENCY_DEMAND_SLICE_CAP:" + MAX_SELECTED_CLASSES);
        }
        LoadResult sliced = new LoadResult(selected, input.diagnostics(), input.filesScanned(),
                input.targetMajorVersion(), List.copyOf(reasons));
        int selectedDependencies = dependencyCount(selected, applicationClassNames);
        return new Result(sliced, true, available.size(), selected.size(), inputDependencies,
                selectedDependencies, capability.size(), anchors.size(), rounds, capped);
    }

    /**
     * Return the resolved classes for fragments whose complete semantic anchor set is present.
     * Resolution mirrors FragmentKnowledgeSource's exact/unique-simple-name policy so a
     * shaded/repackaged artifact is not rejected merely because the rule keeps the upstream
     * owner name.  A fragment with one missing or ambiguous anchor is not admitted at all.
     */
    private static Set<String> completeFragmentAnchorClasses(RuleSet rules,
                                                               Map<String, ClassInfo> available) {
        Set<String> result = new TreeSet<>();
        if (rules == null || available == null || available.isEmpty()) {
            return result;
        }
        for (Rule.FragmentRule fragment : rules.fragments()) {
            if (fragment == null) {
                continue;
            }
            Set<String> names = new LinkedHashSet<>();
            addName(names, fragment.entryClass());
            addName(names, fragment.sinkOwner());
            if (fragment.hops() != null) {
                for (Rule.HopSpec hop : fragment.hops()) {
                    if (hop != null) {
                        addName(names, hop.cls());
                    }
                }
            }
            Set<String> resolved = new TreeSet<>();
            boolean complete = !names.isEmpty();
            for (String name : names) {
                String match = resolveAvailableName(name, available.keySet());
                if (match == null) {
                    complete = false;
                    break;
                }
                resolved.add(match);
            }
            if (complete) {
                result.addAll(resolved);
            }
        }
        return result;
    }

    /** Exact match first, then a unique simple-name suffix match (same as fragment emission). */
    private static String resolveAvailableName(String name, Set<String> available) {
        if (name == null || name.isBlank() || available == null || available.isEmpty()) {
            return null;
        }
        if (available.contains(name)) {
            return name;
        }
        int slash = name.lastIndexOf('/');
        String suffix = "/" + (slash < 0 ? name : name.substring(slash + 1));
        String hit = null;
        for (String candidate : available) {
            if (candidate != null && candidate.endsWith(suffix)) {
                if (hit != null) {
                    return null;
                }
                hit = candidate;
            }
        }
        return hit;
    }

    private static int dependencyCount(Map<String, ClassInfo> classes,
                                       Set<String> applicationClassNames) {
        if (classes == null || classes.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (String name : classes.keySet()) {
            if (applicationClassNames == null || !applicationClassNames.contains(name)) {
                count++;
            }
        }
        return count;
    }

    private static Set<String> ruleAnchors(RuleSet rules, Map<String, ClassInfo> available) {
        Set<String> anchors = new TreeSet<>();
        for (Rule.SinkRule rule : rules.sinks()) {
            addLiteralOwner(anchors, rule == null ? null : rule.call());
        }
        for (Rule.SourceRule rule : rules.sources()) {
            addLiteralOwner(anchors, rule == null ? null : rule.call());
        }
        for (Rule.ModelRule rule : rules.models()) {
            addLiteralOwner(anchors, rule == null ? null : rule.call());
        }
        for (Rule.MagicEntryRule rule : rules.magicEntries()) {
            if (rule != null) {
                addName(anchors, rule.implementsType());
            }
        }
        for (Rule.FragmentRule rule : rules.fragments()) {
            if (rule == null) {
                continue;
            }
            addName(anchors, rule.entryClass());
            addName(anchors, rule.sinkOwner());
            if (rule.hops() != null) {
                for (Rule.HopSpec hop : rule.hops()) {
                    if (hop != null) {
                        addName(anchors, hop.cls());
                    }
                }
            }
        }
        // Condition facts are consumed after composition, but their artifact-owned policy
        // classes must survive the conservative dependency slice.  Retain only literal owners
        // declared by the condition; calibration still requires the actual bytecode call and a
        // known path type before it can reject a chain.
        for (Rule.ConditionRule rule : rules.conditions()) {
            if (rule == null) {
                continue;
            }
            addName(anchors, rule.targetClass().isRegex() ? null : rule.targetClass().pattern());
            if (rule.spec() instanceof Rule.SerializationGuard guard) {
                addLiteralOwner(anchors, guard.guardCall());
            } else if (rule.spec() instanceof Rule.SerializationPackagePolicy policy) {
                addLiteralOwner(anchors, policy.policyCall());
            } else if (rule.spec() instanceof Rule.PropertyFilterDecl filter) {
                addName(anchors, filter.registrationOwner().isRegex()
                        ? null : filter.registrationOwner().pattern());
                addName(anchors, filter.markerClass().isRegex()
                        ? null : filter.markerClass().pattern());
            }
        }
        anchors.removeIf(name -> !available.containsKey(name));
        return anchors;
    }

    private static void addLiteralOwner(Set<String> output, Rule.CallMatcher matcher) {
        if (matcher != null && matcher.owner() != null && !matcher.owner().isRegex()) {
            addName(output, matcher.owner().pattern());
        }
    }

    private static Set<String> directReferences(Set<String> application,
                                                Map<String, ClassInfo> available) {
        Set<String> result = new TreeSet<>();
        if (application == null) {
            return result;
        }
        for (String name : application) {
            ClassInfo info = available.get(name);
            if (info != null) {
                referencesOf(info).stream().filter(available::containsKey).forEach(result::add);
            }
        }
        return result;
    }

    private static Set<String> capabilityClasses(Map<String, ClassInfo> available,
                                                  RuleSet rules, Set<String> anchors,
                                                  Set<String> application,
                                                  Set<String> directApplicationReferences) {
        Set<String> result = new TreeSet<>();
        for (ClassInfo info : available.values()) {
            if (!matchesMagicEntry(info, available, rules.magicEntries())) {
                continue;
            }
            if (hasStrongDeserializeCallback(info, rules.magicEntries())
                    || (anchors != null && anchors.contains(info.internalName()))
                    || (application != null && application.contains(info.internalName()))
                    || (directApplicationReferences != null
                    && directApplicationReferences.contains(info.internalName())
                    && containsRuleCall(info, rules))) {
                result.add(info.internalName());
            }
        }
        return result;
    }

    /**
     * Identify an application-owned boundary using only immutable frontend facts.  This is a
     * demand hint, not the final external-control proof (the graph index owns that proof).
     * OIS/framework source calls and explicit lifecycle/main/framework annotations are enough to
     * connect a dependency suffix; ordinary public helpers and deserialize callbacks are not.
     */
    private static boolean hasApplicationBoundary(Set<String> application,
                                                  Map<String, ClassInfo> available,
                                                  RuleSet rules) {
        if (application == null || application.isEmpty()) {
            return false;
        }
        for (String owner : application) {
            ClassInfo info = available.get(owner);
            if (info == null) {
                continue;
            }
            if (hasBoundaryAnnotation(info)) {
                return true;
            }
            if (isServletType(owner, available)) {
                for (MethodInfo method : info.methods()) {
                    if (("service".equals(method.name()) || method.name().startsWith("do"))
                            && (java.lang.reflect.Modifier.isPublic(method.access())
                            || java.lang.reflect.Modifier.isProtected(method.access()))) {
                        return true;
                    }
                }
            }
            for (MethodInfo method : info.methods()) {
                if ("main".equals(method.name())
                        && "([Ljava/lang/String;)V".equals(method.descriptor())
                        && java.lang.reflect.Modifier.isStatic(method.access())) {
                    return true;
                }
                if (containsExternalSource(method, rules)) {
                    return true;
                }
                if (matchesConfiguredLifecycle(method, info, available, rules)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Follow exact bytecode method references from application boundary methods.  A missing
     * target method is treated as an unresolved edge (the owning class is still retained),
     * rather than expanding every method of that class.  This keeps overload-heavy frameworks
     * bounded without turning a parser limitation into a claimed semantic proof.
     */
    private static MethodSelection applicationMethodClosure(
            Set<String> application, Map<String, ClassInfo> available, RuleSet rules) {
        Map<String, Integer> classDepth = new TreeMap<>();
        Map<String, Set<String>> selectedMethods = new TreeMap<>();
        Map<String, List<MethodInfo>> methodsByOwner = new HashMap<>();
        Map<String, Set<String>> reverseCallers = new HashMap<>();
        Set<String> terminalMethods = new TreeSet<>();
        for (ClassInfo info : available.values()) {
            methodsByOwner.put(info.internalName(), info.methods());
            for (MethodInfo method : info.methods()) {
                String methodKey = method.owner() + "#" + method.name()
                        + method.descriptor();
                if (isTerminalMethod(method, rules)) {
                    terminalMethods.add(methodKey);
                }
                for (InsnFact instruction : method.instructions()) {
                    for (Object operand : instruction.operands()) {
                        if (operand instanceof MethodRef ref) {
                            String callee = ref.owner() + "#" + ref.name()
                                    + ref.descriptor();
                            reverseCallers.computeIfAbsent(callee, ignored -> new TreeSet<>())
                                    .add(methodKey);
                        }
                    }
                }
            }
        }
        Set<String> terminalRelevantMethods = reverseMethodClosure(terminalMethods,
                reverseCallers);
        boolean terminalFilterEnabled = !terminalMethods.isEmpty();
        Deque<MethodWork> work = new ArrayDeque<>();
        Set<String> seenMethods = new HashSet<>();
        for (String owner : application) {
            ClassInfo info = available.get(owner);
            if (info == null) {
                continue;
            }
            List<MethodInfo> boundaries = boundaryMethods(info, available, rules);
            if (boundaries.isEmpty()) {
                boundaries = info.methods();
            }
            for (MethodInfo method : boundaries) {
                if (method != null) {
                    work.addLast(new MethodWork(method, 0));
                }
            }
        }
        while (!work.isEmpty()) {
            MethodWork current = work.removeFirst();
            MethodInfo method = current.method();
            String methodKey = method.owner() + "#" + method.name() + method.descriptor();
            if (!seenMethods.add(methodKey)) {
                continue;
            }
            selectedMethods.computeIfAbsent(method.owner(), ignored -> new TreeSet<>())
                    .add(methodKey);
            classDepth.merge(method.owner(), current.depth(), Math::min);
            if (current.depth() >= MAX_REFERENCE_DEPTH || isPlatformType(method.owner())) {
                continue;
            }
            List<String> refs = new ArrayList<>(referencesOfMethod(method));
            Collections.sort(refs);
            for (String reference : refs) {
                if (!available.containsKey(reference)) {
                    continue;
                }
                classDepth.merge(reference, current.depth() + 1, Math::min);
            }
            for (InsnFact instruction : method.instructions()) {
                for (Object operand : instruction.operands()) {
                    if (!(operand instanceof MethodRef ref)
                            || !available.containsKey(ref.owner())) {
                        continue;
                    }
                    List<MethodInfo> targets = methodsByOwner.getOrDefault(ref.owner(), List.of())
                            .stream()
                            .filter(candidate -> ref.name().equals(candidate.name())
                                    && ref.descriptor().equals(candidate.descriptor()))
                            .sorted(java.util.Comparator.comparing(MethodInfo::owner)
                                    .thenComparing(MethodInfo::name)
                                    .thenComparing(MethodInfo::descriptor))
                            .toList();
                    for (MethodInfo target : targets) {
                        String targetKey = target.owner() + "#" + target.name()
                                + target.descriptor();
                        boolean applicationMethod = application.contains(method.owner());
                        boolean relevant = !terminalFilterEnabled
                                || applicationMethod
                                || terminalRelevantMethods.contains(targetKey);
                        if (relevant) {
                            work.addLast(new MethodWork(target, current.depth() + 1));
                        }
                    }
                }
            }
        }
        return new MethodSelection(classDepth, selectedMethods);
    }

    /** Bounded method-level expansion for dependency callback/fragment roots. */
    private static MethodSelection suffixMethodClosure(Set<String> roots,
                                                             Map<String, ClassInfo> available,
                                                             RuleSet rules) {
        Map<String, Integer> classDepth = new TreeMap<>();
        Map<String, Set<String>> selectedMethods = new TreeMap<>();
        if (roots == null || roots.isEmpty()) {
            return new MethodSelection(classDepth, selectedMethods);
        }
        Map<String, List<MethodInfo>> methodsByOwner = new HashMap<>();
        Map<String, Set<String>> reverseCallers = new HashMap<>();
        Set<String> terminalMethods = new TreeSet<>();
        for (ClassInfo info : available.values()) {
            methodsByOwner.put(info.internalName(), info.methods());
            for (MethodInfo method : info.methods()) {
                String methodKey = method.owner() + "#" + method.name()
                        + method.descriptor();
                if (isTerminalMethod(method, rules)) {
                    terminalMethods.add(methodKey);
                }
                for (InsnFact instruction : method.instructions()) {
                    for (Object operand : instruction.operands()) {
                        if (operand instanceof MethodRef ref) {
                            String callee = ref.owner() + "#" + ref.name()
                                    + ref.descriptor();
                            reverseCallers.computeIfAbsent(callee, ignored -> new TreeSet<>())
                                    .add(methodKey);
                        }
                    }
                }
            }
        }
        Set<String> terminalRelevantMethods = reverseMethodClosure(terminalMethods,
                reverseCallers);
        boolean terminalFilterEnabled = !terminalMethods.isEmpty();
        Deque<MethodWork> work = new ArrayDeque<>();
        Set<String> seenMethods = new HashSet<>();
        for (String root : new TreeSet<>(roots)) {
            ClassInfo info = available.get(root);
            if (info == null) {
                continue;
            }
            List<MethodInfo> seeds = info.methods().stream()
                    .filter(method -> isSuffixSeedMethod(method, rules)
                            || containsBridgeSourceCall(method, rules))
                    .toList();
            if (seeds.isEmpty()) {
                // A class-level anchor without a typed method matcher is retained as a
                // conservative root.  Explicit fragments are handled by retainAllMethods;
                // this fallback keeps custom rule sets from losing their only body.
                seeds = info.methods();
            }
            for (MethodInfo method : seeds) {
                if (method != null) {
                    work.addLast(new MethodWork(method, 0));
                }
            }
        }
        while (!work.isEmpty()) {
            MethodWork current = work.removeFirst();
            MethodInfo method = current.method();
            String methodKey = method.owner() + "#" + method.name() + method.descriptor();
            if (!seenMethods.add(methodKey)) {
                continue;
            }
            selectedMethods.computeIfAbsent(method.owner(), ignored -> new TreeSet<>())
                    .add(methodKey);
            classDepth.merge(method.owner(), current.depth(), Math::min);
            if (current.depth() >= MAX_REFERENCE_DEPTH || isPlatformType(method.owner())) {
                continue;
            }
            for (InsnFact instruction : method.instructions()) {
                for (Object operand : instruction.operands()) {
                    if (!(operand instanceof MethodRef ref)
                            || !available.containsKey(ref.owner())) {
                        continue;
                    }
                    List<MethodInfo> targets = methodsByOwner.getOrDefault(ref.owner(), List.of())
                            .stream()
                            .filter(candidate -> ref.name().equals(candidate.name())
                                    && ref.descriptor().equals(candidate.descriptor()))
                            .sorted(java.util.Comparator.comparing(MethodInfo::owner)
                                    .thenComparing(MethodInfo::name)
                                    .thenComparing(MethodInfo::descriptor))
                            .toList();
                    for (MethodInfo target : targets) {
                        String targetKey = target.owner() + "#" + target.name()
                                + target.descriptor();
                        // Permit the first callback/bridge hop from a seed.  Thereafter every
                        // method must be on a bounded reverse path to a terminal impact.
                        if (!terminalFilterEnabled || current.depth() == 0
                                || terminalRelevantMethods.contains(targetKey)) {
                            work.addLast(new MethodWork(target, current.depth() + 1));
                        }
                    }
                }
            }
        }
        return new MethodSelection(classDepth, selectedMethods);
    }

    /**
     * Select only the concrete JDBC implementations that a dynamic application driver boundary
     * can choose.  This is intentionally based on the bytecode type contract, not a driver name,
     * package, artifact id or benchmark answer.  The caller already supplies the complete
     * target/dependency load, so excluding application classes keeps this an explicit
     * dependency fact rather than a new application root.
     */
    private static Set<String> jdbcDriverImplementationClasses(
            Map<String, ClassInfo> available, Set<String> application) {
        if (available == null || available.isEmpty() || application == null
                || application.isEmpty() || !hasDynamicJdbcDriverSelection(application, available)) {
            return Set.of();
        }
        Set<String> result = new TreeSet<>();
        for (ClassInfo info : available.values()) {
            if (info == null || info.isInterface()
                    || application.contains(info.internalName())
                    || info.method("connect", JDBC_CONNECT_DESCRIPTOR) == null) {
                continue;
            }
            if (isSubtype(info.internalName(), JDBC_DRIVER, available)) {
                result.add(info.internalName());
            }
        }
        return Set.copyOf(result);
    }

    /**
     * Recognize the exact dynamic driver-selection shape used by an application.  It is a
     * finite static fact: no class is loaded and no value is evaluated.  Requiring all three
     * operations in order prevents an unrelated JDBC sink from retaining every driver on the
     * class path.
     */
    private static boolean hasDynamicJdbcDriverSelection(Set<String> application,
                                                          Map<String, ClassInfo> available) {
        if (application == null || available == null) {
            return false;
        }
        for (String owner : new TreeSet<>(application)) {
            ClassInfo info = available.get(owner);
            if (info == null) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                int load = -1;
                int instantiate = -1;
                int connect = -1;
                for (int offset = 0; offset < method.instructions().size(); offset++) {
                    InsnFact instruction = method.instructions().get(offset);
                    for (Object operand : instruction.operands()) {
                        if (!(operand instanceof MethodRef ref)) {
                            continue;
                        }
                        if (load < 0 && ("java/net/URLClassLoader".equals(ref.owner())
                                || "java/lang/ClassLoader".equals(ref.owner()))
                                && "loadClass".equals(ref.name())
                                && JDBC_LOAD_CLASS_DESCRIPTOR.equals(ref.descriptor())) {
                            load = offset;
                        } else if (instantiate < 0 && load >= 0
                                && "java/lang/Class".equals(ref.owner())
                                && "newInstance".equals(ref.name())
                                && JDBC_CLASS_NEW_INSTANCE_DESCRIPTOR.equals(ref.descriptor())) {
                            instantiate = offset;
                        } else if (connect < 0 && instantiate >= 0
                                && JDBC_DRIVER.equals(ref.owner())
                                && "connect".equals(ref.name())
                                && JDBC_CONNECT_DESCRIPTOR.equals(ref.descriptor())) {
                            connect = offset;
                        }
                    }
                }
                if (load >= 0 && instantiate > load && connect > instantiate) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Bounded direct bytecode closure rooted at concrete Driver.connect implementations. */
    private static MethodSelection jdbcDriverMethodClosure(Set<String> roots,
                                                            Map<String, ClassInfo> available) {
        Map<String, Integer> classDepth = new TreeMap<>();
        Map<String, Set<String>> selectedMethods = new TreeMap<>();
        if (roots == null || roots.isEmpty() || available == null || available.isEmpty()) {
            return new MethodSelection(classDepth, selectedMethods);
        }
        Map<String, List<MethodInfo>> methodsByOwner = new HashMap<>();
        for (ClassInfo info : available.values()) {
            if (info != null) {
                methodsByOwner.put(info.internalName(), info.methods());
            }
        }
        Map<String, List<String>> directSubtypes = jdbcDirectSubtypes(available);
        Deque<MethodWork> work = new ArrayDeque<>();
        Set<String> seenMethods = new HashSet<>();
        for (String owner : new TreeSet<>(roots)) {
            ClassInfo info = available.get(owner);
            if (info == null) {
                continue;
            }
            MethodInfo connect = info.method("connect", JDBC_CONNECT_DESCRIPTOR);
            if (connect != null) {
                work.addLast(new MethodWork(connect, 0));
            }
        }
        while (!work.isEmpty()) {
            MethodWork current = work.removeFirst();
            MethodInfo method = current.method();
            String methodKey = method.owner() + "#" + method.name() + method.descriptor();
            if (!seenMethods.add(methodKey)) {
                continue;
            }
            selectedMethods.computeIfAbsent(method.owner(), ignored -> new TreeSet<>())
                    .add(methodKey);
            classDepth.merge(method.owner(), current.depth(), Math::min);
            if (current.depth() >= MAX_JDBC_REFERENCE_DEPTH || isPlatformType(method.owner())) {
                continue;
            }
            for (InsnFact instruction : method.instructions()) {
                for (Object operand : instruction.operands()) {
                    if (!(operand instanceof MethodRef ref)) {
                        continue;
                    }
                    List<MethodInfo> targets = jdbcMethodTargets(ref, available,
                            methodsByOwner, directSubtypes);
                    for (MethodInfo target : targets) {
                        work.addLast(new MethodWork(target, current.depth() + 1));
                    }
                }
            }
        }
        return new MethodSelection(classDepth, selectedMethods);
    }

    /**
     * Resolve only the dispatch shape needed by the JDBC closure.  Abstract/interface calls
     * need their loaded concrete targets to expose an implementation body; ordinary class calls
     * stay exact so a common Object/collection call cannot fan out across the dependency set.
     */
    private static List<MethodInfo> jdbcMethodTargets(MethodRef ref,
                                                       Map<String, ClassInfo> available,
                                                       Map<String, List<MethodInfo>> methodsByOwner,
                                                       Map<String, List<String>> directSubtypes) {
        if (ref == null || available == null || methodsByOwner == null) {
            return List.of();
        }
        List<MethodInfo> result = new ArrayList<>();
        for (MethodInfo method : methodsByOwner.getOrDefault(ref.owner(), List.of())) {
            if (ref.name().equals(method.name()) && ref.descriptor().equals(method.descriptor())) {
                result.add(method);
            }
        }
        ClassInfo declaredOwner = available.get(ref.owner());
        MethodInfo declaredMethod = declaredOwner == null ? null
                : declaredOwner.method(ref.name(), ref.descriptor());
        boolean dispatch = declaredOwner != null && (declaredOwner.isInterface()
                || java.lang.reflect.Modifier.isAbstract(declaredOwner.access())
                || (declaredMethod != null
                && java.lang.reflect.Modifier.isAbstract(declaredMethod.access())));
        if (dispatch) {
            Deque<String> work = new ArrayDeque<>();
            Set<String> seen = new HashSet<>();
            work.add(ref.owner());
            while (!work.isEmpty() && result.size() < MAX_JDBC_DISPATCH_TARGETS) {
                String owner = work.removeFirst();
                if (!seen.add(owner)) {
                    continue;
                }
                for (String child : directSubtypes.getOrDefault(owner, List.of())) {
                    ClassInfo candidate = available.get(child);
                    if (candidate == null) {
                        continue;
                    }
                    if (!candidate.isInterface()) {
                        MethodInfo method = candidate.method(ref.name(), ref.descriptor());
                        if (method != null) {
                            result.add(method);
                            if (result.size() >= MAX_JDBC_DISPATCH_TARGETS) {
                                break;
                            }
                        }
                    }
                    work.addLast(child);
                }
            }
        }
        return result.stream()
                .distinct()
                .sorted(java.util.Comparator.comparing(MethodInfo::owner)
                        .thenComparing(MethodInfo::name)
                        .thenComparing(MethodInfo::descriptor))
                .toList();
    }

    /** Deterministic direct subtype index used only by the bounded JDBC closure. */
    private static Map<String, List<String>> jdbcDirectSubtypes(Map<String, ClassInfo> available) {
        Map<String, Set<String>> mutable = new TreeMap<>();
        for (ClassInfo info : available.values()) {
            if (info == null || info.internalName() == null) {
                continue;
            }
            if (info.superName() != null && !info.superName().isBlank()) {
                mutable.computeIfAbsent(info.superName(), ignored -> new TreeSet<>())
                        .add(info.internalName());
            }
            for (String interfaceName : info.interfaces()) {
                if (interfaceName != null && !interfaceName.isBlank()) {
                    mutable.computeIfAbsent(interfaceName, ignored -> new TreeSet<>())
                            .add(info.internalName());
                }
            }
        }
        Map<String, List<String>> result = new TreeMap<>();
        mutable.forEach((owner, children) -> result.put(owner, List.copyOf(children)));
        return result;
    }

    private static void mergeMethodSelection(Map<String, Set<String>> destination,
                                              Map<String, Set<String>> source) {
        if (source == null) {
            return;
        }
        for (Map.Entry<String, Set<String>> entry : source.entrySet()) {
            destination.computeIfAbsent(entry.getKey(), ignored -> new TreeSet<>())
                    .addAll(entry.getValue());
        }
    }

    private static boolean retainMethod(MethodInfo method, Set<String> wanted, RuleSet rules) {
        if (method == null) {
            return false;
        }
        String key = method.owner() + "#" + method.name() + method.descriptor();
        if (wanted != null && wanted.contains(key)) {
            return true;
        }
        // Constructors and class initializers carry type/field setup needed by object-graph
        // constraints even when no direct call edge survives the demand slice.
        if ("<init>".equals(method.name()) || "<clinit>".equals(method.name())) {
            return true;
        }
        return isRuleMethod(method, rules);
    }

    private static boolean isSuffixSeedMethod(MethodInfo method, RuleSet rules) {
        return method != null && (isRuleMethod(method, rules)
                || "<init>".equals(method.name()) || "<clinit>".equals(method.name()));
    }

    private static boolean isRuleMethod(MethodInfo method, RuleSet rules) {
        if (method == null || rules == null) {
            return false;
        }
        for (Rule.SinkRule rule : rules.sinks()) {
            if (rule != null && rule.call() != null
                    && rule.call().matches(method.owner(), method.name(), method.descriptor())) {
                return true;
            }
        }
        for (Rule.SourceRule rule : rules.sources()) {
            if (rule != null && rule.call() != null
                    && rule.call().matches(method.owner(), method.name(), method.descriptor())) {
                return true;
            }
        }
        for (Rule.ModelRule rule : rules.models()) {
            if (rule != null && rule.call() != null
                    && rule.call().matches(method.owner(), method.name(), method.descriptor())) {
                return true;
            }
        }
        for (Rule.MagicEntryRule rule : rules.magicEntries()) {
            if (rule != null && rule.method() != null
                    && rule.method().matches(method.name(), method.descriptor())
                    && (!rule.method().privateOnly()
                    || java.lang.reflect.Modifier.isPrivate(method.access()))) {
                return true;
            }
        }
        for (Rule.ConditionRule rule : rules.conditions()) {
            if (rule == null || rule.spec() == null) {
                continue;
            }
            Rule.CallMatcher conditionCall = conditionCall(rule);
            if (conditionCall != null
                    && conditionCall.matches(method.owner(), method.name(), method.descriptor())) {
                return true;
            }
            if (containsConditionCall(method, conditionCall)) {
                return true;
            }
            if (rule.spec() instanceof Rule.PropertyFilterDecl filter
                    && filter.registrationOwner().matches(method.owner())
                    && filter.registrationMethod().matches(method.name())) {
                return true;
            }
        }
        return false;
    }

    /** Return the bytecode call declared by a condition, when it has one. */
    private static Rule.CallMatcher conditionCall(Rule.ConditionRule rule) {
        if (rule == null || rule.spec() == null) {
            return null;
        }
        if (rule.spec() instanceof Rule.SerializationGuard guard) {
            return guard.guardCall();
        }
        if (rule.spec() instanceof Rule.SerializationPackagePolicy policy) {
            return policy.policyCall();
        }
        return null;
    }

    /** Keep a caller whose body proves that a declared condition call is wired. */
    private static boolean containsConditionCall(MethodInfo method,
                                                  Rule.CallMatcher conditionCall) {
        if (method == null || conditionCall == null) {
            return false;
        }
        for (InsnFact instruction : method.instructions()) {
            for (Object operand : instruction.operands()) {
                if (operand instanceof MethodRef ref
                        && conditionCall.matches(ref.owner(), ref.name(), ref.descriptor())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isTerminalMethod(MethodInfo method, RuleSet rules) {
        if (method == null) {
            return false;
        }
        for (Rule.SinkRule rule : rules.sinks()) {
            if (rule != null && rule.call() != null
                    && rule.call().matches(method.owner(), method.name(), method.descriptor())) {
                return true;
            }
        }
        for (Rule.FragmentRule rule : rules.fragments()) {
            if (rule != null && Objects.equals(rule.sinkOwner(), method.owner())
                    && Objects.equals(rule.sinkName(), method.name())
                    && (rule.sinkDescriptor() == null || rule.sinkDescriptor().isBlank()
                    || Objects.equals(rule.sinkDescriptor(), method.descriptor()))) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> reverseMethodClosure(Set<String> terminals,
                                                    Map<String, Set<String>> reverseCallers) {
        if (terminals == null || terminals.isEmpty()) {
            return Set.of();
        }
        Set<String> relevant = new TreeSet<>(terminals);
        Map<String, Integer> depth = new HashMap<>();
        Deque<String> work = new ArrayDeque<>();
        for (String terminal : terminals) {
            depth.put(terminal, 0);
            work.addLast(terminal);
        }
        final int maxDepth = Math.max(8, MAX_REFERENCE_DEPTH * 2);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            int currentDepth = depth.getOrDefault(current, maxDepth);
            if (currentDepth >= maxDepth) {
                continue;
            }
            for (String caller : reverseCallers.getOrDefault(current, Set.of())) {
                if (relevant.add(caller)) {
                    depth.put(caller, currentDepth + 1);
                    work.addLast(caller);
                }
            }
        }
        return relevant;
    }

    private record MethodSelection(Map<String, Integer> classDepth,
                                   Map<String, Set<String>> methods) {
        private MethodSelection {
            classDepth = classDepth == null ? Map.of() : Map.copyOf(classDepth);
            if (methods == null || methods.isEmpty()) {
                methods = Map.of();
            } else {
                Map<String, Set<String>> copy = new TreeMap<>();
                for (Map.Entry<String, Set<String>> entry : methods.entrySet()) {
                    copy.put(entry.getKey(), Set.copyOf(entry.getValue()));
                }
                methods = Map.copyOf(copy);
            }
        }
    }

    private record MethodWork(MethodInfo method, int depth) {
    }

    private static List<MethodInfo> boundaryMethods(ClassInfo info,
                                                     Map<String, ClassInfo> available,
                                                     RuleSet rules) {
        List<MethodInfo> result = new ArrayList<>();
        if (info == null) {
            return result;
        }
        boolean servlet = isServletType(info.internalName(), available);
        for (MethodInfo method : info.methods()) {
            boolean boundary = "main".equals(method.name())
                    && "([Ljava/lang/String;)V".equals(method.descriptor())
                    && java.lang.reflect.Modifier.isStatic(method.access());
            boundary |= containsExternalSource(method, rules);
            boundary |= matchesConfiguredLifecycle(method, info, available, rules);
            boundary |= hasBoundaryMethodAnnotation(method);
            if (servlet && ("service".equals(method.name()) || method.name().startsWith("do"))
                    && (java.lang.reflect.Modifier.isPublic(method.access())
                    || java.lang.reflect.Modifier.isProtected(method.access()))) {
                boundary = true;
            }
            if (boundary) {
                result.add(method);
            }
        }
        return result;
    }

    private static boolean hasBoundaryMethodAnnotation(MethodInfo method) {
        if (method == null) {
            return false;
        }
        for (String descriptor : method.annotationDescriptors()) {
            if (isBoundaryAnnotation(descriptor)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasBoundaryAnnotation(ClassInfo info) {
        if (info == null) {
            return false;
        }
        for (String descriptor : info.annotationDescriptors()) {
            if (isBoundaryAnnotation(descriptor)) {
                return true;
            }
        }
        for (MethodInfo method : info.methods()) {
            for (String descriptor : method.annotationDescriptors()) {
                if (isBoundaryAnnotation(descriptor)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isBoundaryAnnotation(String descriptor) {
        if (descriptor == null) {
            return false;
        }
        String value = descriptor.toLowerCase(java.util.Locale.ROOT);
        return value.contains("/web/bind/annotation/") || value.endsWith("/path;")
                || value.contains("/jws/webservice;") || value.contains("/jws/webmethod;")
                || value.contains("/servlet/");
    }

    private static boolean isServletType(String owner, Map<String, ClassInfo> available) {
        Deque<String> pending = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        pending.add(owner);
        while (!pending.isEmpty() && seen.size() <= available.size() + 1) {
            String current = pending.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            if (Set.of("javax/servlet/Servlet", "jakarta/servlet/Servlet",
                    "javax/servlet/http/HttpServlet", "jakarta/servlet/http/HttpServlet",
                    "javax/servlet/Filter", "jakarta/servlet/Filter").contains(current)
                    || current.endsWith("/Servlet") || current.endsWith("/Filter")) {
                return true;
            }
            ClassInfo info = available.get(current);
            if (info != null) {
                if (info.superName() != null) {
                    pending.addLast(info.superName());
                }
                pending.addAll(info.interfaces());
            }
        }
        return false;
    }

    private static boolean containsExternalSource(MethodInfo method, RuleSet rules) {
        if (method == null) {
            return false;
        }
        for (InsnFact instruction : method.instructions()) {
            for (Object operand : instruction.operands()) {
                if (!(operand instanceof MethodRef ref)) {
                    continue;
                }
                if (SerializationModel.isOisRead(ref.owner(), ref.name(), ref.descriptor())) {
                    return true;
                }
                for (Rule.SourceRule source : rules.sources()) {
                    if (source != null && source.call() != null
                            && source.call().matches(ref.owner(), ref.name(), ref.descriptor())
                            && (source.tainted() == null || source.tainted().isEmpty())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Find concrete dependency methods that invoke a rule-declared deserialization bridge.
     *
     * <p>Interface dispatch is intentionally not expanded in the application closure: doing
     * so for every framework converter would recreate the pre-CPG dependency explosion.  A
     * source call is different from an arbitrary helper, however: it is the typed boundary at
     * which a second object graph can enter the chain.  Returning only the owners that contain
     * such a call keeps the admission finite and makes the reason visible in the demand-slice
     * completeness record.</p>
     */
    private static Set<String> sourceBridgeHostClasses(Map<String, ClassInfo> available,
                                                       RuleSet rules) {
        if (available == null || available.isEmpty() || rules == null
                || rules.sources().isEmpty()) {
            return Set.of();
        }
        Set<String> result = new TreeSet<>();
        for (ClassInfo info : available.values()) {
            if (info == null) {
                continue;
            }
            if (info.methods().stream().anyMatch(method -> containsBridgeSourceCall(method, rules))) {
                result.add(info.internalName());
            }
        }
        return Set.copyOf(result);
    }

    /** Whether a method body contains a rule-declared deserialization source invocation. */
    private static boolean containsBridgeSourceCall(MethodInfo method, RuleSet rules) {
        if (method == null || rules == null || rules.sources().isEmpty()) {
            return false;
        }
        for (InsnFact instruction : method.instructions()) {
            for (Object operand : instruction.operands()) {
                if (!(operand instanceof MethodRef ref)) {
                    continue;
                }
                for (Rule.SourceRule source : rules.sources()) {
                    if (source != null && "deserialize".equalsIgnoreCase(source.bridge())
                            && source.call() != null
                            && source.call().matches(ref.owner(), ref.name(), ref.descriptor())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean matchesConfiguredLifecycle(MethodInfo method, ClassInfo owner,
                                                      Map<String, ClassInfo> available,
                                                      RuleSet rules) {
        for (Rule.MagicEntryRule rule : rules.magicEntries()) {
            if (rule == null || rule.method() == null
                    || !"lifecycle".equalsIgnoreCase(rule.direction())
                    || !rule.method().matches(method.name(), method.descriptor())) {
                continue;
            }
            if (rule.implementsType() == null
                    || isSubtype(owner.internalName(), rule.implementsType(), available)) {
                return true;
            }
        }
        return false;
    }

    /** Compute a bounded reverse class-reference slice from configured terminal owners. */
    private static Set<String> terminalRelevantClasses(Map<String, ClassInfo> available,
                                                       RuleSet rules) {
        Set<String> terminals = new TreeSet<>();
        for (Rule.SinkRule rule : rules.sinks()) {
            addLiteralOwner(terminals, rule == null ? null : rule.call());
        }
        for (Rule.FragmentRule rule : rules.fragments()) {
            if (rule != null) {
                addName(terminals, rule.sinkOwner());
            }
        }
        terminals.retainAll(available.keySet());
        if (terminals.isEmpty()) {
            return Set.of();
        }
        Map<String, Set<String>> reverse = new HashMap<>();
        for (Map.Entry<String, ClassInfo> entry : available.entrySet()) {
            for (String reference : referencesOf(entry.getValue())) {
                if (available.containsKey(reference)) {
                    reverse.computeIfAbsent(reference, ignored -> new TreeSet<>())
                            .add(entry.getKey());
                }
            }
        }
        Set<String> relevant = new TreeSet<>(terminals);
        Deque<String> work = new ArrayDeque<>(terminals);
        Map<String, Integer> depth = new HashMap<>();
        terminals.forEach(value -> depth.put(value, 0));
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            int currentDepth = depth.getOrDefault(current, MAX_REFERENCE_DEPTH);
            if (currentDepth >= MAX_REFERENCE_DEPTH) {
                continue;
            }
            for (String caller : reverse.getOrDefault(current, Set.of())) {
                if (relevant.add(caller)) {
                    depth.put(caller, currentDepth + 1);
                    work.addLast(caller);
                }
            }
        }
        return relevant;
    }

    /**
     * readObject/readResolve and the other deserialize callbacks are precise roots. Generic
     * object methods are intentionally not global roots: every serializable library class has
     * an equals/hashCode/toString implementation, and treating those as capabilities recreated
     * the all-dependency graph explosion this slice is meant to prevent. Explicit fragment
     * anchors and application-reachable generic methods are still admitted above.
     */
    private static boolean hasStrongDeserializeCallback(ClassInfo info,
                                                        List<Rule.MagicEntryRule> rules) {
        if (info == null || rules == null) {
            return false;
        }
        for (Rule.MagicEntryRule rule : rules) {
            if (rule == null || rule.method() == null
                    || !"deserialize".equalsIgnoreCase(rule.direction())) {
                continue;
            }
            String kind = rule.entryKind() == null ? "" : rule.entryKind().toLowerCase(
                    java.util.Locale.ROOT);
            if (Set.of("hashcode", "equals", "compareto", "compare", "tostring", "finalize")
                    .contains(kind)) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                if (rule.method().matches(method.name(), method.descriptor())
                        && (!rule.method().privateOnly()
                        || java.lang.reflect.Modifier.isPrivate(method.access()))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean matchesMagicEntry(ClassInfo info, Map<String, ClassInfo> available,
                                             List<Rule.MagicEntryRule> rules) {
        if (info == null || rules == null) {
            return false;
        }
        for (Rule.MagicEntryRule rule : rules) {
            if (rule == null || rule.method() == null) {
                continue;
            }
            if (rule.implementsType() != null
                    && !isSubtype(info.internalName(), rule.implementsType(), available)) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                if (rule.method().matches(method.name(), method.descriptor())
                        && (!rule.method().privateOnly()
                        || java.lang.reflect.Modifier.isPrivate(method.access()))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isSubtype(String name, String expected,
                                     Map<String, ClassInfo> available) {
        if (name == null || expected == null) {
            return false;
        }
        Deque<String> pending = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        pending.add(name);
        while (!pending.isEmpty() && seen.size() <= available.size() + 1) {
            String current = pending.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            if (expected.equals(current)) {
                return true;
            }
            ClassInfo info = available.get(current);
            if (info == null) {
                continue;
            }
            if (info.superName() != null) {
                pending.addLast(info.superName());
            }
            pending.addAll(info.interfaces());
        }
        return false;
    }

    private static boolean containsRuleCall(ClassInfo info, RuleSet rules) {
        if (info == null) {
            return false;
        }
        for (MethodInfo method : info.methods()) {
            for (InsnFact insn : method.instructions()) {
                Object operand = insn.operands().isEmpty() ? null : insn.operands().get(0);
                if (!(operand instanceof MethodRef ref)) {
                    continue;
                }
                if (matchesAny(ref, rules.sinks(), Rule.SinkRule::call)
                        || matchesAny(ref, rules.sources(), Rule.SourceRule::call)
                        || matchesAny(ref, rules.models(), Rule.ModelRule::call)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static <T> boolean matchesAny(MethodRef ref, List<T> rules,
                                           java.util.function.Function<T, Rule.CallMatcher> call) {
        if (ref == null || rules == null) {
            return false;
        }
        for (T rule : rules) {
            Rule.CallMatcher matcher = rule == null ? null : call.apply(rule);
            if (matcher != null && matcher.matches(ref.owner(), ref.name(), ref.descriptor())) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> referencesOf(ClassInfo info) {
        return referencesOfMethods(info, info == null ? List.of() : info.methods());
    }

    private static Set<String> referencesOfMethod(MethodInfo method) {
        Set<String> result = new LinkedHashSet<>();
        if (method == null) {
            return result;
        }
        addDescriptor(result, method.descriptor());
        for (InsnFact instruction : method.instructions()) {
            for (Object operand : instruction.operands()) {
                addOperand(result, operand);
            }
        }
        method.tryCatch().forEach(tc -> addName(result, tc.type()));
        return result;
    }

    private static Set<String> referencesOfMethods(ClassInfo info,
                                                   java.util.Collection<MethodInfo> methods) {
        Set<String> result = new LinkedHashSet<>();
        if (info == null) {
            return result;
        }
        addName(result, info.superName());
        if (info.interfaces() != null) {
            info.interfaces().forEach(name -> addName(result, name));
        }
        for (FieldInfo field : info.fields()) {
            addDescriptor(result, field.descriptor());
            field.genericReferenceTypes().forEach(name -> addName(result, name));
        }
        for (MethodInfo method : methods == null ? List.<MethodInfo>of() : methods) {
            addDescriptor(result, method.descriptor());
            for (InsnFact insn : method.instructions()) {
                for (Object operand : insn.operands()) {
                    addOperand(result, operand);
                }
            }
            method.tryCatch().forEach(tc -> addName(result, tc.type()));
        }
        result.removeIf(Objects::isNull);
        return result;
    }

    private static void addOperand(Set<String> output, Object operand) {
        if (operand instanceof MethodRef ref) {
            addName(output, ref.owner());
            addDescriptor(output, ref.descriptor());
        } else if (operand instanceof FieldRef ref) {
            addName(output, ref.owner());
            addDescriptor(output, ref.descriptor());
        } else if (operand instanceof TypeRef ref) {
            addDescriptor(output, ref.descriptor());
        } else if (operand instanceof HandleRef ref) {
            addName(output, ref.owner());
            addDescriptor(output, ref.descriptor());
        } else if (operand instanceof InvokeDynamicRef ref) {
            addDescriptor(output, ref.descriptor());
            if (ref.bootstrap() != null) {
                addName(output, ref.bootstrap().owner());
                addDescriptor(output, ref.bootstrap().descriptor());
            }
            if (ref.bootstrapArgs() != null) {
                ref.bootstrapArgs().forEach(value -> addOperand(output, value));
            }
        } else if (operand instanceof List<?> values) {
            values.forEach(value -> addOperand(output, value));
        }
    }

    private static void addDescriptor(Set<String> output, String descriptor) {
        if (descriptor == null || descriptor.isBlank()) {
            return;
        }
        int start = -1;
        for (int i = 0; i < descriptor.length(); i++) {
            char value = descriptor.charAt(i);
            if (value == 'L') {
                start = i + 1;
            } else if (value == ';' && start >= 0) {
                addName(output, descriptor.substring(start, i));
                start = -1;
            }
        }
        // TypeRef facts may carry an internal name rather than a descriptor.
        if (start < 0 && descriptor.indexOf('/') >= 0 && descriptor.indexOf('(') < 0) {
            addName(output, descriptor.replace("[", ""));
        }
    }

    private static void addName(Set<String> output, String name) {
        if (name == null || name.isBlank()) {
            return;
        }
        String normalized = name.trim();
        while (normalized.startsWith("[")) {
            normalized = normalized.substring(1);
        }
        if (normalized.startsWith("L") && normalized.endsWith(";")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (normalized.indexOf('/') < 0 && normalized.indexOf('.') >= 0) {
            normalized = normalized.replace('.', '/');
        }
        if (!normalized.isBlank() && normalized.indexOf('(') < 0
                && normalized.indexOf(';') < 0) {
            output.add(normalized);
        }
    }

    private static boolean isPlatformType(String name) {
        if (name == null) {
            return false;
        }
        return name.startsWith("java/") || name.startsWith("javax/")
                || name.startsWith("jdk/") || name.startsWith("sun/")
                || name.startsWith("com/sun/") || name.equals("module-info");
    }
}
