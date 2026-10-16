package net.hugmesh.commons.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the PUBLISH PATH of this library. hugmesh-commons had no GitHub workflow at all
 * until 2026-09-17 (hugmesh/hugmesh-commons#4), which made it the hard stop in the
 * net.hugmesh chain: nothing downstream could be published because nothing could publish
 * IT. None of what follows is reachable from a unit test of the Java code, and each item
 * is a way the path can look finished while publishing nothing, or publishing the wrong
 * thing.
 *
 * <ol>
 *   <li><b>No workflow fires on its own.</b> Publish-on-merge republishes whatever version
 *       {@code pom.xml} holds over an already-published, immutable coordinate — the failure
 *       that forced hugmesh-auth-core's 2.4.2 re-pin. The check is an ALLOWLIST over EVERY
 *       workflow file, not a blacklist of {@code push} spellings in one of them.</li>
 *   <li><b>Resolution is CI-only.</b> {@code maven.pkg.github.com} answers 401 to an
 *       unauthenticated GET (measured 2026-09-17; 401 again with a classic token lacking
 *       {@code read:packages}), so its URL may appear ONLY in
 *       {@code .github/maven-ci-settings.xml}, which reaches a build only via {@code -s}.
 *       In {@code pom.xml} it would break every developer build and
 *       {@code hugmesh-generator/tests/stack/m2-bootstrap.sh}, the cold compose build that
 *       operator decision 27 deliberately KEEPS as the mechanism.</li>
 *   <li><b>Both artifacts ship.</b> hugmesh-auth-core's test scope compiles against
 *       {@code net.hugmesh:hugmesh-commons:2.1.0:tests}. The {@code tests} classifier comes
 *       from maven-jar-plugin's {@code test-jar} goal, which packages {@code target/test-classes}
 *       — so {@code -DskipTests} (skips execution, still compiles) is correct and
 *       {@code -Dmaven.test.skip=true} (skips compilation too) would publish an EMPTY
 *       classifier and break the next link at test-compile, where it reads like an
 *       auth-core problem.</li>
 * </ol>
 *
 * <p>Everything here reads the PARSED document rather than the raw text, for the reason
 * hugmesh-auth-core's ReleaseMetadataGuardTest records: a guard that matches one SPELLING of
 * a config file fails OPEN on every other spelling of the same meaning, and a flag that
 * survives only in a YAML comment is not a flag. Comments do not exist after parsing, and
 * every YAML spelling of a trigger collapses to the same key set. Note {@code on:} is a
 * YAML 1.1 boolean, which is why {@link #triggerNames} also looks up {@link Boolean#TRUE}.
 */
class ReleasePublishGuardTest {

    private static final String RELEASE_WORKFLOW = ".github/workflows/release.yml";
    private static final String CI_SETTINGS = ".github/maven-ci-settings.xml";
    private static final String CI_SETTINGS_FLAG = "-s " + CI_SETTINGS;
    private static final String PACKAGES_HOST = "maven.pkg.github.com";
    private static final String DEPLOY_OVERRIDE =
            "-DaltDeploymentRepository=github::default::https://maven.pkg.github.com/";

    /** The only trigger any workflow here may carry. Anything else publishes without a human. */
    private static final Set<String> ONLY_ALLOWED_TRIGGER = Set.of("workflow_dispatch");

    /** The links BEFORE this one. commons resolves these two and never itself. */
    private static final List<String> UPSTREAM_REPOS =
            List.of("hugmesh-build-config", "hugmesh-parent");

    private static Path repoRoot() {
        return Path.of(System.getProperty("basedir", System.getProperty("user.dir", ".")));
    }

    private static String read(String relative) throws Exception {
        Path p = repoRoot().resolve(relative);
        assertThat(p).as("%s must exist — it is part of the release contract", relative).exists();
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    private static Map<?, ?> parseWorkflow(String relative) throws Exception {
        Object doc = new Yaml(new SafeConstructor(new LoaderOptions())).load(read(relative));
        assertThat(doc).as("%s must parse as a YAML mapping — Actions cannot run it otherwise",
                relative).isInstanceOf(Map.class);
        return (Map<?, ?>) doc;
    }

    private static List<Path> workflowFiles() throws Exception {
        Path dir = repoRoot().resolve(".github/workflows");
        assertThat(dir).as(".github/workflows must exist — issue #4 was that it did not").isDirectory();
        try (Stream<Path> paths = Files.list(dir)) {
            List<Path> files = paths.filter(Files::isRegularFile)
                    .filter(f -> {
                        String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                        return n.endsWith(".yml") || n.endsWith(".yaml");
                    })
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
            assertThat(files).as("no workflow files — this guard would pass vacuously").isNotEmpty();
            return files;
        }
    }

    /** Trigger names, whatever YAML shape they were written in. */
    private static Set<String> triggerNames(Map<?, ?> workflow, String name) {
        Object on = workflow.containsKey(Boolean.TRUE) ? workflow.get(Boolean.TRUE) : workflow.get("on");
        assertThat(on).as("%s declares no `on:` block — not a shape this guard can check, so "
                + "fail rather than pass vacuously", name).isNotNull();

        Set<String> names = new LinkedHashSet<>();
        if (on instanceof Map<?, ?> m) {
            m.keySet().forEach(k -> names.add(String.valueOf(k)));
        } else if (on instanceof Iterable<?> it) {
            it.forEach(e -> {
                if (e instanceof Map<?, ?> em) {
                    em.keySet().forEach(k -> names.add(String.valueOf(k)));
                } else {
                    names.add(String.valueOf(e));
                }
            });
        } else {
            names.add(String.valueOf(on));
        }
        names.remove("true");
        if (String.valueOf(on).equals("true")) {
            names.add("on");
        }
        return names;
    }

    /** Every shell command the workflow actually runs. A flag in a comment is NOT here. */
    private static List<String> runCommands(Map<?, ?> workflow, String name) {
        List<String> commands = new ArrayList<>();
        Object jobs = workflow.get("jobs");
        assertThat(jobs).as("%s declares no jobs", name).isInstanceOf(Map.class);
        for (Object job : ((Map<?, ?>) jobs).values()) {
            if (job instanceof Map<?, ?> jobMap && jobMap.get("steps") instanceof Iterable<?> steps) {
                for (Object step : steps) {
                    if (step instanceof Map<?, ?> stepMap && stepMap.get("run") instanceof String run) {
                        commands.add(run);
                    }
                }
            }
        }
        return commands;
    }

    private static Document parseXml(String relative) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        return f.newDocumentBuilder().parse(new File(repoRoot().resolve(relative).toString()));
    }

    /** {@code <id>} to {@code <url>} for every element of the given tag. */
    private static Map<String, String> xmlEntries(String relative, String tag) throws Exception {
        Map<String, String> out = new LinkedHashMap<>();
        NodeList nodes = parseXml(relative).getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            String id = null;
            String url = "";
            NodeList kids = nodes.item(i).getChildNodes();
            for (int k = 0; k < kids.getLength(); k++) {
                Node kid = kids.item(k);
                if (kid.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                if ("id".equals(kid.getNodeName())) {
                    id = kid.getTextContent().trim();
                } else if ("url".equals(kid.getNodeName())) {
                    url = kid.getTextContent().trim();
                }
            }
            if (id != null) {
                out.put(id, url);
            }
        }
        return out;
    }

    private static List<String> mavenCommands() throws Exception {
        List<String> runs = runCommands(parseWorkflow(RELEASE_WORKFLOW), RELEASE_WORKFLOW);
        List<String> mavens = runs.stream()
                .filter(c -> c.matches("(?s).*(^|\\s)\\./mvnw(\\s|$).*")
                        || c.matches("(?s).*(^|\\s)mvn(\\s|$).*"))
                .toList();
        assertThat(mavens)
                .as("%s runs no maven command at all — the publish step is gone, or is no "
                        + "longer a `run:` step this guard can read. Parsed commands: %s",
                        RELEASE_WORKFLOW, runs)
                .isNotEmpty();
        return mavens;
    }

    @Test
    @DisplayName("a release workflow exists at all — issue #4 was that it did not")
    void releaseWorkflowExists() throws Exception {
        assertThat(repoRoot().resolve(RELEASE_WORKFLOW))
                .as("%s must exist. Without it this library cannot be published, and because "
                        + "hugmesh-auth-core depends on it, nothing downstream can be published "
                        + "either — that is hugmesh/hugmesh-commons#4 in one sentence.",
                        RELEASE_WORKFLOW)
                .exists();
    }

    @Test
    @DisplayName("every maven command passes the CI-only settings file")
    void releaseResolvesThroughTheCiSettingsFile() throws Exception {
        assertThat(repoRoot().resolve(CI_SETTINGS))
                .as("%s must exist — it is the whole resolution route for a CI build. The "
                        + "effective repository list here is Maven Central alone, and this "
                        + "pom's own <parent> net.hugmesh:hugmesh-parent:2.8.0 is 404 there.",
                        CI_SETTINGS)
                .exists();

        for (String cmd : mavenCommands()) {
            assertThat(cmd)
                    .as("every maven invocation in %s must pass `%s`. `-s` REPLACES the user "
                            + "settings file, so a command that omits it gets neither the "
                            + "upstream repositories (fails at parent resolution) nor the "
                            + "`github` server entry (deploy uploads unauthenticated). "
                            + "Offending command: %s", RELEASE_WORKFLOW, CI_SETTINGS_FLAG, cmd)
                    .contains(CI_SETTINGS_FLAG);
        }
    }

    @Test
    @DisplayName("the CI settings file covers both upstream links, as repository AND pluginRepository")
    void ciSettingsCoversTheUpstreamChain() throws Exception {
        Map<String, String> repositories = xmlEntries(CI_SETTINGS, "repository");
        Map<String, String> pluginRepositories = xmlEntries(CI_SETTINGS, "pluginRepository");
        Map<String, String> servers = xmlEntries(CI_SETTINGS, "server");

        for (String upstream : UPSTREAM_REPOS) {
            String expectedUrl = "https://" + PACKAGES_HOST + "/hugmesh/" + upstream;
            assertThat(repositories.values())
                    .as("%s declares no <repository> for %s. GitHub Packages is per-repository "
                            + "(there is no org-wide Maven endpoint). Declared: %s",
                            CI_SETTINGS, upstream, repositories)
                    .contains(expectedUrl);
            assertThat(pluginRepositories.values())
                    .as("%s declares no <pluginRepository> for %s. Maven resolves a PLUGIN's "
                            + "<dependencies> from the PLUGIN repositories, and hugmesh-parent "
                            + "puts net.hugmesh:hugmesh-build-config on the PMD/Checkstyle/"
                            + "SpotBugs plugin classpaths — a repositories-only file resolves "
                            + "the parent POM and then dies at `verify` on the ruleset jar. "
                            + "Declared: %s", CI_SETTINGS, upstream, pluginRepositories)
                    .contains(expectedUrl);
        }

        assertThat(servers.keySet())
                .as("%s must carry a <server> for every repository id it declares, or Maven "
                        + "sends no credential and GitHub Packages answers 401 even for a read. "
                        + "Repository ids: %s; server ids: %s",
                        CI_SETTINGS, repositories.keySet(), servers.keySet())
                .containsAll(repositories.keySet())
                .containsAll(pluginRepositories.keySet());

        assertThat(servers)
                .as("%s must also carry the `github` <server>: `-s` replaces the settings file "
                        + "actions/setup-java generates, so without it the deploy step's "
                        + "%s… uploads with no credential. Server ids: %s",
                        CI_SETTINGS, DEPLOY_OVERRIDE, servers.keySet())
                .containsKey("github");
    }

    @Test
    @DisplayName("the GitHub Packages URL never leaks into the normal, unauthenticated build")
    void packagesRepositoryStaysOutOfThePomAndTheGitlabSettings() throws Exception {
        for (String everydayFile : List.of("pom.xml", "settings.xml")) {
            assertThat(read(everydayFile))
                    .as("%s names %s. That host answers 401 to an unauthenticated GET, so "
                            + "declaring it here breaks every developer `./mvnw verify` and "
                            + "hugmesh-generator/tests/stack/m2-bootstrap.sh — the cold compose "
                            + "build that operator decision 27 deliberately KEEPS as the "
                            + "mechanism. The URL belongs in %s and nowhere else.",
                            everydayFile, PACKAGES_HOST, CI_SETTINGS)
                    .doesNotContain(PACKAGES_HOST);
        }
    }

    @Test
    @DisplayName("deploy overrides the inherited GitLab distributionManagement")
    void deployTargetsGitHubPackagesForThisRepository() throws Exception {
        List<String> deploys = mavenCommands().stream()
                .filter(c -> c.matches("(?s).*\\bdeploy\\b.*"))
                .toList();
        assertThat(deploys)
                .as("%s runs no deploy command — the publish step is gone", RELEASE_WORKFLOW)
                .isNotEmpty();

        for (String deploy : deploys) {
            assertThat(deploy)
                    .as("this pom declares no <distributionManagement>, so it inherits "
                            + "hugmesh-parent's: id `gitlab-maven`, url the literal, "
                            + "uninterpolated ${env.CI_API_V4_URL}/projects/${env.CI_PROJECT_ID}"
                            + "/packages/maven. Without %s the step aims a `gitlab-maven` server "
                            + "id at a non-URL while the only provisioned credential is for the "
                            + "`github` id. Offending command: %s", DEPLOY_OVERRIDE, deploy)
                    .contains(DEPLOY_OVERRIDE);
            assertThat(deploy)
                    .as("the altDeploymentRepository URL must resolve to THIS repo — "
                            + "${{ github.repository }} or the literal hugmesh/hugmesh-commons. "
                            + "Offending command: %s", deploy)
                    .satisfiesAnyOf(
                            s -> assertThat(s).contains(DEPLOY_OVERRIDE + "${{ github.repository }}"),
                            s -> assertThat(s).contains(DEPLOY_OVERRIDE + "hugmesh/hugmesh-commons"));
        }
    }

    @Test
    @DisplayName("the tests classifier is still built and still published")
    void testJarIsBoundAndNotSkippedAway() throws Exception {
        NodeList goals = parseXml("pom.xml").getElementsByTagName("goal");
        Set<String> boundGoals = new LinkedHashSet<>();
        for (int i = 0; i < goals.getLength(); i++) {
            boundGoals.add(goals.item(i).getTextContent().trim());
        }
        assertThat(boundGoals)
                .as("pom.xml no longer binds maven-jar-plugin's `test-jar` goal, so no "
                        + "`tests` classifier is produced. hugmesh-auth-core's test scope "
                        + "compiles against net.hugmesh:hugmesh-commons:2.1.0:tests "
                        + "(PostgresTestSupport) — dropping it breaks the NEXT link of the "
                        + "chain, at test-compile, where it reads like an auth-core problem. "
                        + "Bound goals found: %s", boundGoals)
                .contains("test-jar");

        for (String cmd : mavenCommands()) {
            assertThat(cmd)
                    .as("%s must never pass -Dmaven.test.skip. It skips test COMPILATION, not "
                            + "just execution, so target/test-classes is empty and the "
                            + "`tests` classifier publishes as an EMPTY jar — a publish that "
                            + "reports success and breaks hugmesh-auth-core's test compile. "
                            + "`-DskipTests` is the correct flag: it skips execution and still "
                            + "compiles. Offending command: %s", RELEASE_WORKFLOW, cmd)
                    .doesNotContain("maven.test.skip");
        }
    }

    // ===================================================================================
    // Cross-repo package reads (added 2026-09-18, after adversarial review of the decision
    // 27 round). The prepared chain reads GitHub Packages published from OTHER repositories.
    // secrets.GITHUB_TOKEN is scoped to the repository whose workflow is running, and GitHub
    // does not grant it cross-repository package access, so the build must present a token
    // carrying read:packages. Decision 90a = B (2026-09-23): PACKAGES_READ_TOKEN is the only
    // route; per-package "Manage Actions access" grants are not the plan. Nothing in the
    // first cut presented such a token, and the resulting maven
    // error is "Could not resolve net.hugmesh:..." — the exact string RELEASING.md teaches a
    // reader to interpret as "the upstream is not published yet". These checks pin the fix.
    // ===================================================================================

    /** The env var pair the upstream <server> entries read their credential from. */
    private static final String UPSTREAM_ACTOR = "${env.UPSTREAM_PACKAGES_ACTOR}";
    private static final String UPSTREAM_TOKEN = "${env.UPSTREAM_PACKAGES_TOKEN}";

    /** Every step of a workflow, as parsed maps. */
    private static List<Map<?, ?>> steps(Map<?, ?> workflow) {
        List<Map<?, ?>> out = new ArrayList<>();
        if (workflow.get("jobs") instanceof Map<?, ?> jobs) {
            for (Object job : jobs.values()) {
                if (job instanceof Map<?, ?> jobMap && jobMap.get("steps") instanceof Iterable<?> list) {
                    for (Object step : list) {
                        if (step instanceof Map<?, ?> stepMap) {
                            out.add(stepMap);
                        }
                    }
                }
            }
        }
        return out;
    }

    /** {@code <server>} id to its literal [username, password] in a settings file. */
    private static Map<String, List<String>> serverCredentials(String relative) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        Document doc = f.newDocumentBuilder().parse(new File(repoRoot().resolve(relative).toString()));
        Map<String, List<String>> out = new java.util.LinkedHashMap<>();
        NodeList servers = doc.getElementsByTagName("server");
        for (int i = 0; i < servers.getLength(); i++) {
            String id = null;
            String user = "";
            String pass = "";
            NodeList kids = servers.item(i).getChildNodes();
            for (int k = 0; k < kids.getLength(); k++) {
                Node kid = kids.item(k);
                if (kid.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                switch (kid.getNodeName()) {
                    case "id" -> id = kid.getTextContent().trim();
                    case "username" -> user = kid.getTextContent().trim();
                    case "password" -> pass = kid.getTextContent().trim();
                    default -> { }
                }
            }
            if (id != null) {
                out.put(id, List.of(user, pass));
            }
        }
        assertThat(out).as("%s declares no <server> entries at all", relative).isNotEmpty();
        return out;
    }

    /** Recursively: does any {@code permissions:} block in this document mention packages? */
    private static boolean grantsPackagesPermission(Object node) {
        if (node instanceof Map<?, ?> m) {
            Object perms = m.get("permissions");
            if (perms instanceof Map<?, ?> pm && pm.containsKey("packages")) {
                return true;
            }
            if ("write-all".equals(String.valueOf(perms))) {
                return true;
            }
            for (Object v : m.values()) {
                if (grantsPackagesPermission(v)) {
                    return true;
                }
            }
        } else if (node instanceof Iterable<?> it) {
            for (Object v : it) {
                if (grantsPackagesPermission(v)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Can this workflow publish an immutable coordinate, directly or by dispatching something
     * that does?
     *
     * <p>The classifier is deliberately lopsided: EXEMPTION is hard to obtain and easy to lose.
     * A workflow counts as publishing if ANY of these hold — a parsed {@code run:} command
     * invokes the {@code deploy} phase/goal; a parsed {@code run:} command dispatches another
     * workflow ({@code gh workflow run}); any {@code permissions:} block in it mentions
     * {@code packages}; or the RAW file text names {@code maven.pkg.github.com} at all,
     * comments included. The raw-text clause is on the INCLUDING side on purpose — a comment
     * that mentions the registry makes a workflow stricter, never looser, which is the
     * opposite of the fail-open direction this class was burned by before.
     *
     * <p><b>Why this is not simply "every workflow".</b> Measured 2026-09-18: the
     * all-workflows form failed a plain {@code ci.yml} running {@code ./mvnw test} on
     * {@code pull_request}, with the message "Every workflow in this repo publishes or can
     * publish an immutable coordinate" — which is false of a test-only workflow. This repo has
     * no pre-merge CI workflow yet, so that guard would have gone red in the face of the first
     * person wiring one up (the 116-of-126 pre-merge gate programme), for a reason with
     * nothing to do with releases. A guard that blocks the correct change is a guard people
     * delete.
     */
    private static boolean canPublish(String relative) throws Exception {
        if (read(relative).contains(PACKAGES_HOST)) {
            return true;
        }
        Map<?, ?> workflow = parseWorkflow(relative);
        if (grantsPackagesPermission(workflow)) {
            return true;
        }
        for (String cmd : runCommands(workflow, relative)) {
            if (cmd.matches("(?s).*\\bdeploy\\b.*") || cmd.contains("workflow run")) {
                return true;
            }
        }
        return false;
    }

    @Test
    @DisplayName("every workflow that CAN publish is dispatch-only — and release.yml is always classified as one")
    void everyPublishingWorkflowIsDispatchOnly() throws Exception {
        List<String> publishing = new ArrayList<>();
        List<String> exempt = new ArrayList<>();
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString().replace('\\', '/');
            if (!canPublish(relative)) {
                exempt.add(relative);
                continue;
            }
            publishing.add(relative);
            Set<String> triggers = triggerNames(parseWorkflow(relative), relative);
            assertThat(triggers)
                    .as("%s can publish an immutable coordinate and declares triggers %s. "
                            + "Any trigger other than workflow_dispatch — push, pull_request, "
                            + "release, schedule, workflow_run, repository_dispatch — republishes "
                            + "whatever version pom.xml happens to hold over a coordinate that is "
                            + "already out there. If a new trigger is deliberate, widen "
                            + "ONLY_ALLOWED_TRIGGER in the same change and say why in RELEASING.md. "
                            + "(Workflows this run treated as NON-publishing, and therefore free to "
                            + "carry any trigger: %s — see canPublish().)",
                            relative, triggers, exempt)
                    .containsExactlyInAnyOrderElementsOf(ONLY_ALLOWED_TRIGGER);
        }
        assertThat(publishing)
                .as("canPublish() exempted the release workflow itself, so this guard just passed "
                        + "vacuously over the one file it exists for. Classified as publishing: %s; "
                        + "exempt: %s.", publishing, exempt)
                .contains(RELEASE_WORKFLOW);
    }

    @Test
    @DisplayName("cross-repo package reads do NOT ride on the repository-scoped GITHUB_TOKEN")
    void upstreamReadsCarryTheirOwnOverridableCredential() throws Exception {
        Map<String, List<String>> servers = serverCredentials(CI_SETTINGS);

        assertThat(servers.get("github"))
                .as("the DEPLOY server must keep the automatic ${env.GITHUB_TOKEN}. A workflow "
                        + "may always write packages for the repository it runs in, so requiring "
                        + "an operator-held secret for the deploy half would be a regression, not "
                        + "a fix. Declared: %s", servers)
                .containsExactly("${env.GITHUB_ACTOR}", "${env.GITHUB_TOKEN}");

        for (Map.Entry<String, List<String>> e : servers.entrySet()) {
            if ("github".equals(e.getKey())) {
                continue;
            }
            assertThat(e.getValue())
                    .as("<server id=%s> authenticates a READ of packages published from ANOTHER "
                            + "repository. secrets.GITHUB_TOKEN is scoped to the repository whose "
                            + "workflow is running; GitHub does not grant it cross-repo package "
                            + "access (the per-package 'Manage Actions access' grant is not "
                            + "the plan, decision 90a = B). Wiring this server to "
                            + "${env.GITHUB_TOKEN} makes the whole chain depend on a credential "
                            + "that cannot read it, and it fails "
                            + "as 'Could not resolve net.hugmesh:...' — the exact string "
                            + "RELEASING.md teaches a reader to interpret as 'the upstream is not "
                            + "published yet', so the first real run gets MISDIAGNOSED. Use %s / "
                            + "%s, which release.yml injects from secrets.PACKAGES_READ_TOKEN with "
                            + "a GITHUB_TOKEN fallback. See RELEASING.md 6.2.",
                            e.getKey(), UPSTREAM_ACTOR, UPSTREAM_TOKEN)
                    .containsExactly(UPSTREAM_ACTOR, UPSTREAM_TOKEN);
        }
    }

    @Test
    @DisplayName("release.yml injects that read credential into every settings-file maven step, overridably")
    void releaseWorkflowInjectsTheUpstreamReadCredential() throws Exception {
        int checked = 0;
        for (Map<?, ?> step : steps(parseWorkflow(RELEASE_WORKFLOW))) {
            if (!(step.get("run") instanceof String run) || !run.contains(CI_SETTINGS_FLAG)) {
                continue;
            }
            checked++;
            Object env = step.get("env");
            assertThat(env)
                    .as("step '%s' runs maven with %s but declares no env: block, so "
                            + "${env.UPSTREAM_PACKAGES_TOKEN} in the settings file expands to "
                            + "nothing and every upstream read goes out unauthenticated (401).",
                            step.get("name"), CI_SETTINGS_FLAG)
                    .isInstanceOf(Map.class);
            Map<?, ?> envMap = (Map<?, ?>) env;
            String token = String.valueOf(envMap.get("UPSTREAM_PACKAGES_TOKEN"));
            List<String> envKeys = envMap.keySet().stream().map(String::valueOf).toList();
            assertThat(envKeys)
                    .as("step '%s' must inject UPSTREAM_PACKAGES_ACTOR and "
                            + "UPSTREAM_PACKAGES_TOKEN. Declared: %s",
                            step.get("name"), envKeys)
                    .contains("UPSTREAM_PACKAGES_ACTOR", "UPSTREAM_PACKAGES_TOKEN");
            assertThat(token)
                    .as("step '%s' wires UPSTREAM_PACKAGES_TOKEN to '%s'. It must offer the "
                            + "operator's read:packages PAT FIRST and fall back to the automatic "
                            + "token: ${{ secrets.PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN }}. "
                            + "Hardcoding secrets.GITHUB_TOKEN alone leaves the chain with a "
                            + "credential that cannot read other repositories' packages and no "
                            + "way for an operator to override it.", step.get("name"), token)
                    .contains("secrets.PACKAGES_READ_TOKEN")
                    .contains("secrets.GITHUB_TOKEN");
        }
        assertThat(checked)
                .as("no step in %s runs maven with %s — this guard just passed vacuously",
                        RELEASE_WORKFLOW, CI_SETTINGS_FLAG)
                .isGreaterThan(0);
    }

    @Test
    @DisplayName("the cross-repo read is preflighted, and the one route to authorise it is written down")
    void crossRepoPackageReadIsPreflightedAndDocumented() throws Exception {
        List<Map<?, ?>> preflights = steps(parseWorkflow(RELEASE_WORKFLOW)).stream()
                .filter(s -> String.valueOf(s.get("name")).toLowerCase(Locale.ROOT).startsWith("preflight"))
                .toList();
        assertThat(preflights)
                .as("%s has no Preflight step. Without it, a credential that cannot read an "
                        + "upstream registry surfaces only as maven's 'Could not resolve "
                        + "net.hugmesh:...', which is indistinguishable from 'not published yet' "
                        + "and sends the operator off to re-publish something that is already "
                        + "there. The preflight exists to name that failure correctly.",
                        RELEASE_WORKFLOW)
                .hasSize(1);

        String script = String.valueOf(preflights.get(0).get("run"));
        for (String upstream : UPSTREAM_REPOS) {
            assertThat(script)
                    .as("the preflight never probes hugmesh/%s, so a credential that cannot read "
                            + "that upstream gets past it. Upstreams: %s", upstream, UPSTREAM_REPOS)
                    .contains(upstream);
        }
        assertThat(script)
                .as("the preflight must tell 401/403 (cannot authenticate) apart from 404 "
                        + "(nothing published, OR published and masked). Collapsing them is the "
                        + "misdiagnosis this step exists to prevent. Script: %s", script)
                .contains("401").contains("403").contains("404");
        assertThat(String.valueOf(preflights.get(0).get("env")))
                .as("the preflight must probe with the SAME credential maven will use, or a green "
                        + "preflight proves nothing about the build that follows it.")
                .contains("UPSTREAM_PACKAGES_TOKEN");

        String releasing = read("RELEASING.md");
        assertThat(releasing)
                .as("RELEASING.md must name PACKAGES_READ_TOKEN: decision 90a = B made it the sole "
                        + "route, and it is the credential the workflow reads.")
                .contains("PACKAGES_READ_TOKEN");
        assertThat(releasing)
                .as("RELEASING.md may mention the per-package 'Manage Actions access' grant only "
                        + "as the route that is not the plan (decision 90a = B). Presenting it as "
                        + "a launch-day step or an alternative sends the operator to a setting "
                        + "that is probably not offered for Maven packages.")
                .contains("*Not the plan:* per-package **Manage Actions access**");
        String notThePlan = "*Not the plan:* per-package **Manage Actions access**";
        assertThat(releasing.replaceAll("\\s+", " ").replace(notThePlan, ""))
                .as("RELEASING.md mentions 'Manage Actions access' outside the '*Not the plan:*' "
                        + "bullet. Decision 90a = B made PACKAGES_READ_TOKEN the only route, so any "
                        + "other mention reads as a live option or a launch-day step.")
                .doesNotContainIgnoringCase("Manage Actions access");
    }
}
