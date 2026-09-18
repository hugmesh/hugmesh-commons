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
    @DisplayName("no workflow in this repo fires on its own")
    void everyWorkflowIsDispatchOnly() throws Exception {
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString();
            Set<String> triggers = triggerNames(parseWorkflow(relative), relative);
            assertThat(triggers)
                    .as("%s declares triggers %s. Any trigger other than workflow_dispatch — "
                            + "push, pull_request, release, schedule, workflow_run — publishes "
                            + "whatever version pom.xml happens to hold, over an already-"
                            + "published immutable coordinate. If a new trigger is deliberate, "
                            + "widen ONLY_ALLOWED_TRIGGER in the same change and say why in "
                            + "RELEASING.md.", relative, triggers)
                    .containsExactlyInAnyOrderElementsOf(ONLY_ALLOWED_TRIGGER);
        }
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
}
