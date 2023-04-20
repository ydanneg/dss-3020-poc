import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
    kotlin("jvm") version "1.8.0"
}

group = "com.ydanneg"
version = "1.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    val bouncyCastleVersion = "1.72"
    testImplementation("org.bouncycastle:bcpkix-jdk15to18:$bouncyCastleVersion")
    testImplementation("org.bouncycastle:bcprov-jdk15to18:$bouncyCastleVersion")

    val dssVersion = "5.12.RC1"
    testImplementation("eu.europa.ec.joinup.sd-dss:dss-token:$dssVersion")
    testImplementation("eu.europa.ec.joinup.sd-dss:dss-spi:$dssVersion")
    testImplementation("eu.europa.ec.joinup.sd-dss:dss-service:$dssVersion")
    testImplementation("eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons:$dssVersion")
    testImplementation("eu.europa.ec.joinup.sd-dss:dss-asic-xades:$dssVersion")
    testImplementation("ee.sk.smartid:smart-id-java-client:2.2.2")
    testRuntimeOnly("com.sun.xml.bind:jaxb-impl:2.3.4")
    testRuntimeOnly("org.glassfish.jersey.inject:jersey-hk2:3.0.4")
    testRuntimeOnly("javax.xml.bind:jaxb-api:2.3.1")
    testImplementation("org.slf4j:slf4j-api:2.0.5")
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.5")
    testImplementation(kotlin("test-junit5"))
    testImplementation("io.kotest:kotest-assertions-core:5.5.5")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

tasks {
    test {
        useJUnitPlatform()
        testLogging {
            showStandardStreams = true
            exceptionFormat = TestExceptionFormat.FULL
            events("skipped", "failed")
        }
    }
}