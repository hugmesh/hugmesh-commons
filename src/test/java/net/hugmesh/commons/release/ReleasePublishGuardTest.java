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
 *   <li><b>Only a person publishes.</b> Publish-on-merge republishes whatever version
 *       {@code pom.xml} holds over an already-published, immutable coordinate — the failure
 *       that forced hugmesh-auth-core's 2.4.2 re-pin. A publishing workflow may carry only
 *       {@code workflow_dispatch} and a {@code push} that is restricted to {@code v*} TAGS
 *       (the beta scheme of 2026-10-21: the tag is the decision to publish). The check is an
 *       ALLOWLIST over EVERY workflow file, not a blacklist of {@code push} spellings in one
 *       of them, and the deploy step itself runs only when the version guard said the ref
 *       is a {@code v<version>} tag equal to {@code pom.xml}'s version.</li>
 *   <li><b>Resolution is CI-only.</b> {@code maven.pkg.github.com} answers 401 to an
 *       unauthenticated GET (measured 2026-09-17; 401 again with a classic token lacking
 *       {@code read:packages}), so its URL may appear ONLY in
 *       {@code .github/maven-ci-settings.xml}, which reaches a build only via {@code -s}.
 *       In {@code pom.xml} it would break every developer build and
 *       {@code hugmesh-generator/tests/stack/m2-bootstrap.sh}, the cold compose build that
 *       operator decision 27 deliberately KEEPS as the mechanism.</li>
 *   <li><b>Both artifacts ship.</b> hugmesh-auth-core's test scope compiles against
 *       {@code net.hugmesh:hugmesh-commons:<version>:tests}. The {@code tests} classifier comes
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

    /**
     * The only triggers a publishing workflow may carry. {@code push} is allowed ONLY in its
     * tag-restricted form (see {@link #assertPushIsTagOnly}); anything else publishes without
     * a human deciding to.
     */
    private static final Set<String> ALLOWED_TRIGGERS = Set.of("workflow_dispatch", "push");

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
                        + "pom's own <parent> net.hugmesh:hugmesh-parent is 404 there.",
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
                        + "compiles against net.hugmesh:hugmesh-commons:<version>:tests "
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
    @DisplayName("every workflow that CAN publish starts only by dispatch or a v* tag push — and release.yml is always classified as one")
    void everyPublishingWorkflowIsDispatchOrTagOnly() throws Exception {
        List<String> publishing = new ArrayList<>();
        List<String> exempt = new ArrayList<>();
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString().replace('\\', '/');
            if (!canPublish(relative)) {
                exempt.add(relative);
                continue;
            }
            publishing.add(relative);
            Map<?, ?> workflow = parseWorkflow(relative);
            Set<String> triggers = triggerNames(workflow, relative);
            assertThat(ALLOWED_TRIGGERS)
                    .as("%s can publish an immutable coordinate and declares triggers %s. "
                            + "Only workflow_dispatch and a v*-tag-only push are allowed — "
                            + "pull_request, release, schedule, workflow_run, repository_dispatch "
                            + "or a branch push republishes whatever version pom.xml happens to "
                            + "hold over a coordinate that is already out there. If a new trigger "
                            + "is deliberate, widen ALLOWED_TRIGGERS in the same change and say "
                            + "why in RELEASING.md. (Workflows this run treated as NON-publishing, "
                            + "and therefore free to carry any trigger: %s — see canPublish().)",
                            relative, triggers, exempt)
                    .containsAll(triggers);
            assertThat(triggers)
                    .as("%s must keep workflow_dispatch: it is the re-run path for a tag whose "
                            + "first run failed. Declared: %s", relative, triggers)
                    .contains("workflow_dispatch");
            if (triggers.contains("push")) {
                assertPushIsTagOnly(onBlock(workflow), relative);
            }
        }
        assertThat(publishing)
                .as("canPublish() exempted the release workflow itself, so this guard just passed "
                        + "vacuously over the one file it exists for. Classified as publishing: %s; "
                        + "exempt: %s.", publishing, exempt)
                .contains(RELEASE_WORKFLOW);
    }

    /** The parsed {@code on:} value ({@code on} is a YAML 1.1 boolean, see the class doc). */
    private static Object onBlock(Map<?, ?> workflow) {
        return workflow.containsKey(Boolean.TRUE) ? workflow.get(Boolean.TRUE) : workflow.get("on");
    }

    /**
     * A {@code push} trigger fires on EVERY branch and tag push unless it is narrowed. The
     * only acceptable shape is a mapping whose sole key is {@code tags}, every pattern of
     * which starts with {@code v} followed by a digit or a glob — so no {@code branches},
     * no {@code branches-ignore}, no {@code tags-ignore} and no {@code paths} (a
     * {@code paths}-only push still fires on every branch).
     */
    private static void assertPushIsTagOnly(Object on, String relative) {
        assertThat(on)
                .as("%s lists `push` without any filter (list or scalar form of `on:`), so it "
                        + "fires on every branch push — publish-on-merge.", relative)
                .isInstanceOf(Map.class);
        Object push = ((Map<?, ?>) on).get("push");
        assertThat(push)
                .as("%s has `push:` with no filter at all, which fires on every branch push.",
                        relative)
                .isInstanceOf(Map.class);
        Map<?, ?> pushMap = (Map<?, ?>) push;
        assertThat(pushMap.keySet().stream().map(String::valueOf).toList())
                .as("%s: `push:` must be narrowed by `tags:` and nothing else. `branches` "
                        + "publishes on merge; `paths`/`tags-ignore`/`branches-ignore` widen it "
                        + "back to branch pushes. Declared keys: %s", relative, pushMap.keySet())
                .containsExactly("tags");
        Object tags = pushMap.get("tags");
        assertThat(tags).as("%s: `push.tags` must be a non-empty list", relative)
                .isInstanceOf(List.class);
        assertThat((List<?>) tags).as("%s: `push.tags` is empty", relative).isNotEmpty();
        for (Object pattern : (List<?>) tags) {
            assertThat(String.valueOf(pattern))
                    .as("%s: tag pattern '%s' must start with `v` (the v<version> release tag); "
                            + "a bare `*` or `**` makes every tag a publish.", relative, pattern)
                    .matches("v[0-9*].*");
        }
    }

    // ===================================================================================
    // Beta scheme (2026-10-21). The tag push above is only safe because of three more
    // things: the deploy step runs only on kind=release, the version guard that sets kind
    // refuses every ref except main and a v<version> tag equal to pom.xml's version, and a
    // self-hosted runner is chosen only for a non-PR event on main or a release tag.
    // ===================================================================================

    /** The exact runs-on line every job of the release workflow uses (beta scheme 3.1). */
    static final String PUBLISH_RUNS_ON = "${{ fromJSON(github.event_name != 'pull_request' "
            + "&& github.event_name != 'pull_request_target' && (github.ref == 'refs/heads/main' "
            + "|| startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/tags/studio-v')) "
            + "&& vars.RUNS_ON_PUBLISH || '\"ubuntu-latest\"') }}";

    private static Map<?, ?> jobs(Map<?, ?> workflow, String name) {
        Object jobs = workflow.get("jobs");
        assertThat(jobs).as("%s declares no jobs", name).isInstanceOf(Map.class);
        return (Map<?, ?>) jobs;
    }

    @Test
    @DisplayName("the deploy step runs only when the version guard said kind=release")
    void deployRunsOnlyForAReleaseTag() throws Exception {
        Map<?, ?> workflow = parseWorkflow(RELEASE_WORKFLOW);
        int deploys = 0;
        for (Map.Entry<?, ?> job : jobs(workflow, RELEASE_WORKFLOW).entrySet()) {
            if (!(job.getValue() instanceof Map<?, ?> jobMap)
                    || !(jobMap.get("steps") instanceof Iterable<?> list)) {
                continue;
            }
            for (Object step : list) {
                if (step instanceof Map<?, ?> stepMap && stepMap.get("run") instanceof String run
                        && run.matches("(?s).*\\bdeploy\\b.*")) {
                    deploys++;
                    String condition = String.valueOf(stepMap.get("if")) + " " + String.valueOf(jobMap.get("if"));
                    assertThat(condition.replaceAll("\\s+", ""))
                            .as("step '%s' in job '%s' deploys, but neither it nor its job is "
                                    + "gated on `needs.version.outputs.kind == 'release'`. Without "
                                    + "that, a dispatch on main deploys pom.xml's version — the "
                                    + "publish-without-a-tag this scheme exists to prevent. "
                                    + "Conditions found: %s", stepMap.get("name"), job.getKey(), condition)
                            .contains("needs.version.outputs.kind=='release'");
                    assertThat(String.valueOf(jobMap.get("needs")))
                            .as("job '%s' deploys but does not need the `version` job, so "
                                    + "needs.version.outputs.kind is always empty.", job.getKey())
                            .contains("version");
                }
            }
        }
        assertThat(deploys).as("no deploy step found — this guard passed vacuously").isPositive();
    }

    /** The {@code run:} script of the step with this id, in any job. */
    private static String stepScript(Map<?, ?> workflow, String stepId) {
        for (Map<?, ?> step : steps(workflow)) {
            if (stepId.equals(String.valueOf(step.get("id"))) && step.get("run") instanceof String run) {
                return run;
            }
        }
        throw new AssertionError("no step with id '" + stepId + "' and a run: script in "
                + RELEASE_WORKFLOW + " — the version guard is gone");
    }

    private record GuardRun(int exit, String output, String stdout) { }

    private static GuardRun runVersionGuard(String script, String ref, String version) throws Exception {
        Path dir = Files.createTempDirectory("version-guard");
        try {
            Path scriptFile = dir.resolve("guard.sh");
            Path out = dir.resolve("github_output");
            Files.writeString(scriptFile, script, StandardCharsets.UTF_8);
            Files.writeString(out, "", StandardCharsets.UTF_8);
            ProcessBuilder pb = new ProcessBuilder("bash", "-e", scriptFile.toString())
                    .directory(dir.toFile())
                    .redirectErrorStream(true);
            pb.environment().put("GITHUB_REF", ref);
            pb.environment().put("VERSION", version);
            pb.environment().put("GITHUB_OUTPUT", out.toString());
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = p.waitFor();
            return new GuardRun(exit, Files.readString(out, StandardCharsets.UTF_8), stdout);
        } finally {
            try (Stream<Path> files = Files.list(dir)) {
                for (Path f : files.toList()) {
                    Files.deleteIfExists(f);
                }
            }
            Files.deleteIfExists(dir);
        }
    }

    private static boolean bashAvailable() {
        try {
            return new ProcessBuilder("bash", "-c", "exit 0").start().waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Test
    @DisplayName("the version guard publishes only a v<version> tag equal to the pom version, and refuses every other ref")
    void versionGuardDecidesFromRefAndPomVersion() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(bashAvailable(),
                "bash is not on PATH here, so the guard script cannot be executed");
        String script = stepScript(parseWorkflow(RELEASE_WORKFLOW), "guard");
        assertThat(script)
                .as("the version guard must read only env vars; a ${{ }} expression in it is "
                        + "substituted by Actions and would make this test run a different "
                        + "script than the runner does")
                .doesNotContain("${{");

        GuardRun release = runVersionGuard(script, "refs/tags/v2.2.0-beta.1", "2.2.0-beta.1");
        assertThat(release.exit()).as("matching beta tag must pass: %s", release.stdout()).isZero();
        assertThat(release.output()).contains("kind=release").contains("version=2.2.0-beta.1");

        GuardRun fin = runVersionGuard(script, "refs/tags/v2.2.0", "2.2.0");
        assertThat(fin.exit()).as("matching final tag must pass: %s", fin.stdout()).isZero();
        assertThat(fin.output()).contains("kind=release");

        GuardRun main = runVersionGuard(script, "refs/heads/main", "2.2.0-beta.1");
        assertThat(main.exit()).as("dispatch on main must pass as a verify-only run: %s", main.stdout()).isZero();
        assertThat(main.output()).contains("kind=main").doesNotContain("kind=release");

        String[][] refused = {
            {"refs/tags/v2.2.0-beta.2", "2.2.0-beta.1", "tag does not match the pom"},
            {"refs/tags/v2.2.0", "2.2.0-beta.1", "final tag on a beta pom"},
            {"refs/tags/2.2.0-beta.1", "2.2.0-beta.1", "tag without the v prefix"},
            {"refs/tags/studio-v2.2.0-beta.1", "2.2.0-beta.1", "another artifact's tag prefix"},
            {"refs/heads/feature/x", "2.2.0-beta.1", "a feature branch"},
            {"refs/heads/mainline", "2.2.0-beta.1", "a branch that only starts with main"},
            {"refs/pull/7/merge", "2.2.0-beta.1", "a pull request ref"},
            {"refs/tags/v2.2.0-SNAPSHOT", "2.2.0-SNAPSHOT", "a SNAPSHOT version"},
            {"refs/heads/main", "2.2.0-SNAPSHOT", "a SNAPSHOT version on main"},
            {"refs/tags/v2.2.0-rc.1", "2.2.0-rc.1", "a version outside the beta scheme"},
            {"refs/tags/v", "", "an empty version"},
        };
        for (String[] c : refused) {
            GuardRun r = runVersionGuard(script, c[0], c[1]);
            assertThat(r.exit())
                    .as("the version guard must REFUSE %s (ref %s, pom version '%s'), but exited 0 "
                            + "with outputs %s", c[2], c[0], c[1], r.output())
                    .isNotZero();
            assertThat(r.output())
                    .as("a refused run must not set kind (ref %s)", c[0])
                    .doesNotContain("kind=");
        }
    }

    @Test
    @DisplayName("pom.xml carries a version the release guard can publish (MAJOR.MINOR.PATCH[-beta.N])")
    void pomVersionFollowsTheBetaScheme() throws Exception {
        Node project = parseXml("pom.xml").getDocumentElement();
        String version = null;
        NodeList kids = project.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            if (kids.item(i).getNodeType() == Node.ELEMENT_NODE
                    && "version".equals(kids.item(i).getNodeName())) {
                version = kids.item(i).getTextContent().trim();
            }
        }
        assertThat(version)
                .as("pom.xml <project><version> must be MAJOR.MINOR.PATCH-beta.N (or a final "
                        + "MAJOR.MINOR.PATCH): the release workflow's version guard refuses "
                        + "anything else, SNAPSHOT included, so a tag for it could never publish.")
                .isNotNull()
                .matches("\\d+\\.\\d+\\.\\d+(-beta\\.\\d+)?");
    }

    @Test
    @DisplayName("release jobs pick the local runner only through the guarded runs-on line")
    void releaseJobsUseTheGuardedRunsOnLine() throws Exception {
        Map<?, ?> workflow = parseWorkflow(RELEASE_WORKFLOW);
        for (Map.Entry<?, ?> job : jobs(workflow, RELEASE_WORKFLOW).entrySet()) {
            assertThat(job.getValue()).isInstanceOf(Map.class);
            assertThat(String.valueOf(((Map<?, ?>) job.getValue()).get("runs-on")))
                    .as("job '%s' in %s must use exactly the beta-scheme runs-on line, which picks "
                            + "vars.RUNS_ON_PUBLISH only for a non-PR event on main or a release "
                            + "tag and hosted ubuntu-latest otherwise", job.getKey(), RELEASE_WORKFLOW)
                    .isEqualTo(PUBLISH_RUNS_ON);
        }
        assertThat(triggerNames(workflow, RELEASE_WORKFLOW))
                .as("%s must never run on pull requests: a self-hosted runner must not run PR code",
                        RELEASE_WORKFLOW)
                .doesNotContain("pull_request", "pull_request_target");
    }

    @Test
    @DisplayName("no workflow asks for a self-hosted runner outside the guarded line")
    void noWorkflowReadsRunsOnOrHardcodesSelfHosted() throws Exception {
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString().replace('\\', '/');
            for (Map.Entry<?, ?> job : jobs(parseWorkflow(relative), relative).entrySet()) {
                if (!(job.getValue() instanceof Map<?, ?> jobMap)) {
                    continue;
                }
                String runsOn = String.valueOf(jobMap.get("runs-on"));
                if (runsOn.equals(PUBLISH_RUNS_ON)) {
                    continue;
                }
                assertThat(runsOn)
                        .as("job '%s' in %s: runs-on '%s' reaches a self-hosted runner without the "
                                + "event/ref guard. PR jobs must say ubuntu-latest literally, and "
                                + "vars.RUNS_ON is retired (beta scheme 3.2).", job.getKey(), relative, runsOn)
                        .doesNotContain("self-hosted")
                        .doesNotContain("RUNS_ON");
            }
        }
    }

    @Test
    @DisplayName("release.yml never writes to the runner host's ~/.m2")
    void releaseLeavesTheHostMavenHomeAlone() throws Exception {
        Map<?, ?> workflow = parseWorkflow(RELEASE_WORKFLOW);
        for (String cmd : mavenCommands()) {
            assertThat(cmd)
                    .as("every maven command must use a local repository under RUNNER_TEMP. On a "
                            + "self-hosted runner ~/.m2/repository is the host's own, shared with "
                            + "every offline build there. Offending command: %s", cmd)
                    .contains("-Dmaven.repo.local=\"${RUNNER_TEMP}/");
        }
        int mvnwSteps = 0;
        for (Map<?, ?> step : steps(workflow)) {
            if (step.get("run") instanceof String run && run.contains("./mvnw")) {
                mvnwSteps++;
                Map<?, ?> env = step.get("env") instanceof Map<?, ?> e ? e : Map.of();
                assertThat(String.valueOf(env.get("MAVEN_USER_HOME")))
                        .as("step '%s' runs ./mvnw without MAVEN_USER_HOME under runner.temp. "
                                + "mvnw then unpacks its Maven download into ~/.m2/wrapper, the "
                                + "host's own on a self-hosted runner. env: %s", step.get("name"), env)
                        .contains("runner.temp");
            }
        }
        assertThat(mvnwSteps).as("no ./mvnw step - this guard passed vacuously").isPositive();
        int setupJava = 0;
        for (Map<?, ?> step : steps(workflow)) {
            if (String.valueOf(step.get("uses")).startsWith("actions/setup-java")) {
                setupJava++;
                Map<?, ?> with = step.get("with") instanceof Map<?, ?> w ? w : Map.of();
                assertThat(with.containsKey("cache"))
                        .as("setup-java `cache:` restores an archive over ~/.m2/repository, the "
                                + "host's own on a self-hosted runner. with: %s", with)
                        .isFalse();
                if (with.containsKey("server-id")) {
                    assertThat(String.valueOf(with.get("settings-path")))
                            .as("setup-java with server-id writes settings.xml to settings-path, "
                                    + "which defaults to ~/.m2 — on a self-hosted runner that "
                                    + "overwrites the host's own ~/.m2/settings.xml. with: %s", with)
                            .contains("runner.temp");
                }
            }
        }
        assertThat(setupJava).as("no setup-java step — this guard passed vacuously").isPositive();
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
