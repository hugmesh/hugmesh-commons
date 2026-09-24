package net.hugmesh.commons.testsupport;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Canonical shared Testcontainers-Postgres base for every HugMesh integration
 * slice. Published as a TEST-JAR so consumers depend on
 * {@code net.hugmesh:hugmesh-commons:2.1.0:tests} (test scope) and
 * simply {@code extends PostgresTestSupport} — ONE base class, ONE container, for
 * the whole org.
 *
 * <h2>Why this shape (the federation exemplar pattern)</h2>
 * <ul>
 *   <li><b>ONE singleton container</b> started in a static block — NOT
 *       {@code @Container} per class. On a busy Docker host the per-class lifecycle
 *       races (every class spinning its own postgres concurrently); a single static
 *       container is started once for the whole JVM and reused.</li>
 *   <li><b>A FRESH database per test class</b> — {@code CREATE DATABASE cmtest_<seq>}
 *       (seq from a static {@link AtomicInteger}) in {@link DynamicPropertySource}.
 *       NOT a single shared db: that leaks Liquibase seeds / fixture rows across
 *       classes and makes tests order-dependent. Each class gets a clean schema,
 *       Liquibase runs against it in isolation.</li>
 *   <li><b>R2DBC + Liquibase both repointed</b> at the fresh db — R2DBC for the
 *       reactive runtime reads/writes, Liquibase (over JDBC) owning the migrations.</li>
 *   <li><b>{@code spring.liquibase.parameters.json.type=text}</b> — harmless where a
 *       changelog never references {@code ${json.type}}; required where one does:
 *       on a real Postgres a {@code jsonb} column is returned as a {@code Json} type,
 *       not a {@code String}, which breaks String-mapped entity fields. Defaulting the
 *       parameter to {@code text} keeps those columns String-compatible. Override per
 *       repo via {@link #jsonTypeOverride()} (return {@code "jsonb"} to opt back in).</li>
 * </ul>
 *
 * <h2>Overriding {@code json.type}</h2>
 * {@link #jsonTypeOverride()} is the seam. Because {@code @DynamicPropertySource} is
 * static (resolved before any instance exists), the override is published into a
 * {@code static volatile} slot the moment a concrete subclass is constructed — and the
 * registered property is a <em>lazy supplier</em>, so Spring reads the up-to-date value
 * after construction. A subclass that maps true {@code jsonb} just overrides the method:
 * <pre>{@code
 *   @Override protected String jsonTypeOverride() { return "jsonb"; }
 * }</pre>
 */
// this-escape: the instance initializer below deliberately calls the overridable
// jsonTypeOverride() before any concrete subclass's own field initializers / constructor
// body have run. This is safe by contract (see jsonTypeOverride() javadoc): every override
// across the org returns a fixed string literal and reads no instance state, so a
// partially-initialized subclass field is never observed.
@SuppressWarnings("this-escape")
public abstract class PostgresTestSupport {

    /**
     * ONE Postgres for the whole test JVM. Static block start (not {@code @Container})
     * so it is reused across every subclass and never races on a busy Docker host.
     */
    protected static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"));

    /** Monotonic per-class database suffix so every test class gets a clean db. */
    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    /**
     * Last-seen {@code ${json.type}} value, published by the instance initializer below
     * from the concrete subclass's {@link #jsonTypeOverride()}. The registered property
     * is a lazy supplier, so it reads this after the subclass is constructed. Defaults
     * to {@code "text"} — the correct baseline for every changelog that never references
     * {@code ${json.type}}.
     */
    private static volatile String jsonType = "text";

    static {
        POSTGRES.start();
    }

    {
        // Publish this concrete subclass's override the moment it is constructed, so the
        // lazy json.type supplier (registered statically) reads the right value.
        jsonType = jsonTypeOverride();
    }

    /**
     * Liquibase {@code ${json.type}} substitution. Defaults to {@code "text"} so
     * jsonb columns stay String-mappable; a repo whose entities map true jsonb can
     * override to return {@code "jsonb"}.
     *
     * <p><strong>Contract:</strong> overrides MUST return a fixed string literal and
     * must NOT read any instance field — this method is invoked from an instance
     * initializer block, before the concrete subclass's own field initializers and
     * constructor body have run.
     */
    protected String jsonTypeOverride() {
        return "text";
    }

    @DynamicPropertySource
    static void registerPostgresProperties(DynamicPropertyRegistry registry) {
        // Fresh database per test class — created over a JDBC admin connection to the
        // singleton container, so classes never share Liquibase seeds or fixture rows.
        final String dbName = "cmtest_" + DB_SEQ.incrementAndGet();
        createDatabase(dbName);

        final String host = POSTGRES.getHost();
        final int port = POSTGRES.getFirstMappedPort();
        final String user = POSTGRES.getUsername();
        final String password = POSTGRES.getPassword();

        // R2DBC — reactive runtime connection factory.
        registry.add("spring.r2dbc.url",
                () -> "r2dbc:postgresql://" + host + ":" + port + "/" + dbName);
        registry.add("spring.r2dbc.username", () -> user);
        registry.add("spring.r2dbc.password", () -> password);

        // Liquibase — migrations run over JDBC against the same fresh db.
        registry.add("spring.liquibase.url",
                () -> "jdbc:postgresql://" + host + ":" + port + "/" + dbName);
        registry.add("spring.liquibase.user", () -> user);
        registry.add("spring.liquibase.password", () -> password);

        // ${json.type} substitution — lazy: read after the subclass instance initializer
        // publishes its jsonTypeOverride(); default "text" (see class javadoc).
        registry.add("spring.liquibase.parameters.json.type", () -> jsonType);
    }

    private static void createDatabase(String dbName) {
        final String adminJdbcUrl = "jdbc:postgresql://"
                + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort()
                + "/" + POSTGRES.getDatabaseName();
        try (var connection = DriverManager.getConnection(
                adminJdbcUrl, POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            // dbName is "cmtest_" + an int — no injection surface; quoted for safety.
            statement.executeUpdate("CREATE DATABASE \"" + dbName + "\"");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create test database " + dbName, e);
        }
    }
}
