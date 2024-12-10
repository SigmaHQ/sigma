pipeline {
    agent any

    environment {
        GIT_REPO_URL = 'https://github.com/SigmaHQ/sigma'
    }

    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()  // Clean workspace before starting the job
                echo "Workspace cleaned."
            }
        }

        stage('Clone Repository') {
            steps {
                // Clone the repository
                git branch: 'master', url: "$GIT_REPO_URL"
            }
        }

        stage('Process YAML Files') {
            steps {
                script {
                    // Find all .yml files, convert them to .spl, and delete the .yml files after conversion
                    sh '''
                        find "${WORKSPACE}/rules" -name '*.yml' | while read file; do
                            # Set output .spl file path
                            spl_file="${file%.yml}.spl"
                            
                            # Run the sigma conversion command for each .yml file
                            sigma convert -t splunk -p sysmon "$file" -o "$spl_file"
                            
                            # Check if conversion was successful
                            if [ $? -eq 0 ]; then
                                echo "Conversion successful: $file -> $spl_file"
                                rm -f "$file"  # Remove original .yml file
                            else
                                echo "Conversion failed for: $file"
                            fi
                        done
                    '''
                }
            }
        }
    }
}
