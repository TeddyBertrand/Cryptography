pipeline {
    agent { label 'rust-agent' }

    options {
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Notify pending') {
            steps {
                githubNotify(
                    credentialsId: 'github-status-token',
                    context: 'continuous-integration/jenkins',
                    status: 'PENDING',
                    description: 'Build started'
                )
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
                sh 'cargo llvm-cov --workspace --cobertura --output-path target/coverage/cobertura.xml'
            }
            post {
                always {
                    recordCoverage(
                        tools: [[parser: 'COBERTURA', pattern: 'target/coverage/cobertura.xml']],
                        qualityGates: [
                            [threshold: 70.0, metric: 'LINE', baseline: 'PROJECT', unstable: true]
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
            githubNotify(
                credentialsId: 'github-status-token',
                context: 'continuous-integration/jenkins',
                status: 'SUCCESS',
                description: 'Build succeeded'
            )
        }
        failure {
            githubNotify(
                credentialsId: 'github-status-token',
                context: 'continuous-integration/jenkins',
                status: 'FAILURE',
                description: 'Build failed'
            )
        }
        always {
            cleanWs()
        }
    }
}
