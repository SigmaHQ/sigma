pipeline {
    agent any

    environment {
        GIT_REPO_URL = 'https://github.com/SigmaHQ/sigma'
        OUTPUT_JSON = 'sigma_coverage.json'
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
                // Clone the repository
                git branch: 'master', url: "$GIT_REPO_URL"
            }
        }

        stage('Generate ATT&CK Coverage') {
            steps {
                script {
                    def techniqueMap = [:] 

                    // List all YAML files in the repository
                    sh '''
                        find "${WORKSPACE}/rules" -name '*.yml' > rule_files.txt
                    '''
                    def ruleFiles = readFile('rule_files.txt').split('\n').findAll { it.trim() }

                    // Process each YAML file
                    ruleFiles.each { ruleFile ->
                        try {
                            echo "Processing file: ${ruleFile}"
                            def content = readYaml file: ruleFile
                            def tags = content?.tags?.findAll { it.startsWith('attack.t') } ?: []
                            tags.each { tag ->
                                def techniqueID = tag.replace('attack.', '')
                                def fileName = ruleFile.split('/')[-1]
                                if (!techniqueMap.containsKey(techniqueID)) {
                                    techniqueMap[techniqueID] = [score: 0, comment: []]
                                }
                                techniqueMap[techniqueID].score += 1
                                techniqueMap[techniqueID].comment.add(fileName)
                            }
                        } catch (Exception e) {
                            echo "Error processing file: ${ruleFile} - ${e.message}"
                        }
                    }

                    // Create JSON output
                    def jsonOutput = [
                        domain: "mitre-enterprise",
                        name: "Sigma rules coverage",
                        gradient: [
                            colors: ["#a0eab5", "#0f480f"],
                            maxValue: techniqueMap.values().max { it.score }?.score ?: 0,
                            minValue: 0
                        ],
                        version: "3.0",
                        techniques: techniqueMap.collect { techniqueID, details ->
                            [
                                techniqueID: techniqueID,
                                score: details.score,
                                comment: details.comment.join('\n')
                            ]
                        }
                    ]

                    writeFile file: env.OUTPUT_JSON, text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(jsonOutput))
                    echo "ATT&CK coverage JSON file generated: ${env.OUTPUT_JSON}"
                }
            }
        }

        stage('Fix Technique ID Formatting') {
            steps {
                script {
                    def jsonContent = readFile(env.OUTPUT_JSON)
                    // Fix formatting of technique IDs
                    def fixedJsonContent = jsonContent.replaceAll(/"techniqueID": "t/, '"techniqueID": "T')
                    writeFile file: env.OUTPUT_JSON, text: fixedJsonContent
                    echo "Technique IDs updated to uppercase in JSON file."
                }
            }
        }
    }

    post {
        success {
            archiveArtifacts artifacts: env.OUTPUT_JSON, fingerprint: true
            echo "Generated and corrected ATT&CK coverage JSON file has been archived."
        }
        failure {
            echo "Pipeline failed. Check the logs for details."
        }
    }
}
