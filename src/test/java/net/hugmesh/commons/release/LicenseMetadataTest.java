package net.hugmesh.commons.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the license of this repository and of the jar it publishes.
 *
 * <p>A public repository with no LICENSE file is "all rights reserved": anyone may read it,
 * nobody may legally reuse it. The published pom is what Maven tooling (and anyone who only
 * sees the jar) reads, so it must name a license too, and it must be the SAME license as the
 * file. hugmesh-parent declares no {@code <licenses>}, so nothing is inherited; the block in
 * this repo's pom.xml is the only one.
 *
 * <p>The pom is read PARSED, and only the direct children of {@code <project>} count, so a
 * license named in a comment or inside some plugin's configuration does not satisfy it.
 */
class LicenseMetadataTest {

    private static final String LICENSE_FILE = "LICENSE";
    private static final String LICENSE_NAME = "MIT License";
    private static final String REPO_URL = "https://github.com/hugmesh/hugmesh-commons";

    private static Path repoRoot() {
        return Path.of(System.getProperty("basedir", System.getProperty("user.dir", ".")));
    }

    private static Element project() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        Document doc = f.newDocumentBuilder()
                .parse(new File(repoRoot().resolve("pom.xml").toString()));
        return doc.getDocumentElement();
    }

    /** Direct element children of {@code parent} with the given tag, in document order. */
    private static List<Element> children(Element parent, String tag) {
        List<Element> out = new ArrayList<>();
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node kid = kids.item(i);
            if (kid.getNodeType() == Node.ELEMENT_NODE && tag.equals(kid.getNodeName())) {
                out.add((Element) kid);
            }
        }
        return out;
    }

    private static String childText(Element parent, String tag) {
        List<Element> found = children(parent, tag);
        return found.isEmpty() ? null : found.get(0).getTextContent().trim();
    }

    @Test
    @DisplayName("the repo root carries the MIT LICENSE text with a copyright line")
    void licenseFileIsPresent() throws Exception {
        Path license = repoRoot().resolve(LICENSE_FILE);
        assertThat(license)
                .as("%s is missing. A public repository without one is all rights reserved, "
                        + "so nobody may reuse the code.", LICENSE_FILE)
                .isRegularFile();
        List<String> lines = Files.readAllLines(license, StandardCharsets.UTF_8).stream()
                .map(String::trim)
                .filter(l -> !l.isEmpty())
                .toList();
        assertThat(lines).as("%s is empty", LICENSE_FILE).isNotEmpty();
        assertThat(lines.get(0))
                .as("%s does not start with the license name the pom declares", LICENSE_FILE)
                .isEqualTo(LICENSE_NAME);
        assertThat(lines).anySatisfy(l -> assertThat(l).startsWith("Copyright (c)"));
        assertThat(String.join(" ", lines))
                .contains("Permission is hereby granted, free of charge");
    }

    @Test
    @DisplayName("the published pom names the same license as the LICENSE file")
    void pomDeclaresTheSameLicense() throws Exception {
        List<Element> blocks = children(project(), "licenses");
        assertThat(blocks)
                .as("pom.xml has no top-level <licenses>, so the published pom names no license")
                .hasSize(1);
        List<Element> licenses = children(blocks.get(0), "license");
        assertThat(licenses).hasSize(1);
        assertThat(childText(licenses.get(0), "name")).isEqualTo(LICENSE_NAME);
        assertThat(childText(licenses.get(0), "url")).isNotBlank();
    }

    @Test
    @DisplayName("the published pom points back at this repository")
    void pomPointsAtTheRepository() throws Exception {
        Element project = project();
        assertThat(childText(project, "url")).isEqualTo(REPO_URL);
        List<Element> scm = children(project, "scm");
        assertThat(scm).as("pom.xml has no top-level <scm>").hasSize(1);
        assertThat(childText(scm.get(0), "url")).isEqualTo(REPO_URL);
        assertThat(childText(scm.get(0), "connection")).isEqualTo("scm:git:" + REPO_URL + ".git");
    }
}
