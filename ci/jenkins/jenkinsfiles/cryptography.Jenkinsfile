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

// Best-effort like notifyGitHub. An empty webhook URL (DISCORD_WEBHOOK_URL
// unset in .env) skips silently. The message goes through the environment
// and the secret through withCredentials, so neither is Groovy-interpolated
// into the shell script.
def notifyDiscord(String message) {
    try {
        withCredentials([string(credentialsId: 'discord-webhook-url', variable: 'DISCORD_WEBHOOK_URL')]) {
            withEnv(["DISCORD_MESSAGE=${message}"]) {
                sh '''
                    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
                        echo "Discord webhook not configured, skipping"
                        exit 0
                    fi
                    printf '{"content":"%s"}' "$DISCORD_MESSAGE" |
                        curl -sSf -H 'Content-Type: application/json' -d @- "$DISCORD_WEBHOOK_URL"
                '''
            }
        }
    } catch (err) {
        echo "Discord notification not sent: ${err.message}"
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
        stage('Build') {
            steps {
                sh 'make re'
            }
        }
        stage('Test') {
            steps {
                sh 'cargo nextest run --workspace --profile ci'
            }
            post {
                always {
                    junit 'target/nextest/ci/junit.xml'
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
            notifyDiscord(":red_circle: ${env.JOB_NAME} #${env.BUILD_NUMBER} failed: ${env.BUILD_URL}")
        }
        fixed {
            notifyDiscord(":green_circle: ${env.JOB_NAME} #${env.BUILD_NUMBER} is back to green: ${env.BUILD_URL}")
        }
        always {
            cleanWs()
        }
    }
}
