import groovy.transform.Field

// Plain pipelineJob (not multibranch): githubNotify can't infer the repo
// from the SCM source, so account/repo/sha are passed explicitly.
def notifyGitHub(String status, String description) {
    // Best-effort: a missing/invalid token or a GitHub outage must not fail
    // the build itself.
    try {
        githubNotify(
            credentialsId: 'github-status-token',
            context: 'continuous-integration/jenkins',
            account: 'TeddyBertrand',
            repo: 'Cryptography',
            sha: env.GIT_COMMIT,
            status: status,
            description: description
        )
    } catch (err) {
        echo "GitHub status not posted: ${err.message}"
    }
}

// Filled by the Test and Coverage stages for the Discord report; @Field
// script fields rather than locals so every stage and method sees them (a
// bare assignment would go through the binding, which Jenkins warns about).
// They stay null when the build stops before their stage.
@Field def testSummary = null
// Tab-separated per-theme results of the Test stage (scripts/test-themes.sh).
@Field def testThemes = ''
@Field def lineCoverage = null

// Best-effort like notifyGitHub: see discord.groovy.
def reportDiscord() {
    try {
        def commit = sh(script: 'git log -1 --format="%h %s"', returnStdout: true).trim()
        def author = sh(script: 'git log -1 --format=%an', returnStdout: true).trim()
        def discord = load 'ci/jenkins/jenkinsfiles/discord.groovy'
        def tests = 'not run'
        if (testSummary != null) {
            def counts = "${testSummary.passCount}/${testSummary.totalCount} passed"
            def skipped = testSummary.skipCount > 0 ? ", ${testSummary.skipCount} skipped" : ''
            tests = "${discord.bar(testSummary.passCount, testSummary.totalCount)}\n**${counts}**${skipped}"
        }
        def coverage = lineCoverage == null ? 'not run' : "${discord.bar((int) Math.round(lineCoverage as double), 100)}\n**${lineCoverage}%** of lines"
        def description = "`${commit}` by ${author}\n\n${discord.testTables(discord.parseThemes(testThemes))}"
        discord.send(
            description: description,
            fields: [discord.field('Tests', tests), discord.field('Coverage', coverage)]
        )
    } catch (err) {
        echo "Discord report not sent: ${err.message}"
    }
}

pipeline {
    agent { label 'rust-agent' }

    options {
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Notify pending') {
            steps {
                notifyGitHub('PENDING', 'Build started')
            }
        }
        stage('Format') {
            steps {
                sh 'cargo fmt --all -- --check'
            }
        }
        stage('Lint') {
            steps {
                sh 'cargo clippy --workspace -- -D warnings'
            }
        }
        stage('Delivery tree') {
            steps {
                sh 'sh scripts/check_delivery.sh'
            }
        }
        stage('Build') {
            steps {
                sh 'make re'
            }
        }
        // Subject examples + bonus flag combinations (crates/my_pgp/tests/cases),
        // its own stage so a retrocompatibility break shows up by name.
        stage('Retrocompat') {
            steps {
                sh 'cargo test -p my_pgp --test functional'
            }
        }
        stage('Test') {
            steps {
                sh 'cargo nextest run --workspace --profile ci'
            }
            post {
                always {
                    script {
                        testSummary = junit 'target/nextest/ci/junit.xml'
                        // Best-effort: no report when the run stopped before writing one.
                        testThemes = sh(
                            script: 'sh ci/jenkins/scripts/test-themes.sh target/nextest/ci/junit.xml || true',
                            returnStdout: true
                        )
                    }
                }
            }
        }
        stage('Delivery check') {
            steps {
                sh '''
                    test -x ./my_pgp
                    ./my_pgp -h
                '''
            }
        }
        stage('Coverage') {
            steps {
                sh 'mkdir -p target/coverage && cargo llvm-cov --workspace --cobertura --output-path target/coverage/cobertura.xml'
                // The root <coverage> element's line-rate is the first one.
                script {
                    lineCoverage = sh(
                        script: '''grep -o 'line-rate="[0-9.]*"' target/coverage/cobertura.xml | head -n 1 | cut -d'"' -f2 | awk '{ printf "%.1f", $1 * 100 }' ''',
                        returnStdout: true
                    ).trim() ?: null
                }
            }
            post {
                always {
                    // llvm-cov emits one <method> per closure instance, so
                    // names like `{closure#0}` repeat within a class; skip
                    // those duplicates instead of rejecting the whole report.
                    recordCoverage(
                        tools: [[parser: 'COBERTURA', pattern: 'target/coverage/cobertura.xml']],
                        ignoreParsingErrors: true,
                        qualityGates: [
                            [threshold: 70.0, metric: 'LINE', baseline: 'PROJECT', criticality: 'UNSTABLE']
                        ]
                    )
                }
            }
        }
        stage('Archive artifact') {
            steps {
                archiveArtifacts artifacts: 'my_pgp', fingerprint: true
            }
        }
        stage('Epitech dump check') {
            agent {
                // reuseNode: rust-agent has a single executor, a second
                // node allocation would wait on the one this build holds.
                docker {
                    image 'epitechcontent/epitest-docker'
                    reuseNode true
                }
            }
            steps {
                sh '''
                    make re
                    test -x ./my_pgp
                    ./my_pgp -h
                    cargo test --workspace
                    cargo test --workspace --release -- --include-ignored
                '''
            }
        }
    }

    post {
        success {
            notifyGitHub('SUCCESS', 'Build succeeded')
        }
        failure {
            notifyGitHub('FAILURE', 'Build failed')
        }
        always {
            reportDiscord()
        }
        // cleanup runs after every other post condition, so the report
        // above still has the workspace (git log, discord.groovy).
        cleanup {
            cleanWs()
        }
    }
}
