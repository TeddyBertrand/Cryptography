pipeline {
    agent { label 'rust-agent' }

    stages {
        stage('Format') {
            steps {
                sh 'cargo fmt --all -- --check'
            }
        }
        stage('Build') {
            steps {
                sh 'cargo build --workspace'
            }
        }
        stage('Test') {
            steps {
                sh 'cargo test --workspace'
            }
        }
        stage('Clippy') {
            steps {
                sh 'cargo clippy --workspace -- -D warnings'
            }
        }
    }
}
