pipeline {
    agent any

    environment {
        GIT_REPO_URL = 'https://github.com/SigmaHQ/sigma'
    }

    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
                echo "Workspace cleaned."
            }
        }

        stage('Clone Repository') {
            steps {
                git branch: 'master', url: "$GIT_REPO_URL"
                echo "Repository cloned: $GIT_REPO_URL"
            }
        }

        stage('Process YAML Files') {
            steps {
                script {
                    sh '''
                        set -e  # Exit on error
                        
                        echo "Starting YAML processing..."
                        
                        # Directory where Sigma rules are stored
                        RULES_DIR="${WORKSPACE}/rules"
                        
                        # Find all .yml files
                        find "$RULES_DIR" -name '*.yml' | while read file; do
                            echo "Processing file: $file"
                            
                            # Set output .spl file path
                            spl_file="${file%.yml}.spl"
                            
                            # Attempt conversion
                            if ! sigma convert -t splunk -p sysmon "$file" -o "$spl_file"; then
                                echo "Conversion failed for: $file"
                                echo "Skipping this file and moving to the next."
                                continue  # Skip the current file and continue with the next one
                            fi
                            
                            echo "Conversion successful: $file -> $spl_file"
                            
                            # Remove the original YAML file
                            rm -f "$file"
                        done
                        
                        echo "YAML processing completed."
                    '''
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline completed."
        }
        success {
            echo "Pipeline executed successfully."
        }
        failure {
            echo "Pipeline execution failed. Please check the logs for details."
        }
    }
}
