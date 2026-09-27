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
