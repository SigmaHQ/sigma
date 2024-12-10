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

        stage('Clone Source Repo') {
            steps {
                checkout([$class: 'GitSCM', 
                    branches: [[name: '*/master']],  // Pull from main branch
                    userRemoteConfigs: [[url: env.GIT_REPO_URL, credentialsId: 'git-credential-id']]
                ])
            }
        }

        stage('Generate ATT&CK Coverage') {
            steps {
                script {
                    def techniqueMap = [:] 

                    // Read all rule files in the repository
                    sh '''
                        find "${WORKSPACE}/rules" -name '*.yml' > rule_files.txt
                    '''

                    def ruleFiles = readFile('rule_files.txt').split('\n').findAll { it.trim() }

                    // Process each rule file
                    ruleFiles.each { ruleFile ->
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
                    }

                    // Create the JSON structure
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

                    // Write to JSON file
                    writeFile file: env.OUTPUT_JSON, text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(jsonOutput))
                    echo "ATT&CK coverage JSON file generated: ${env.OUTPUT_JSON}"
                }
            }
        }

        stage('Fix Technique ID Formatting') {
            steps {
                script {
                    def jsonContent = readFile(env.OUTPUT_JSON)
                    // Replace 't' with 'T' for all technique IDs
                    def fixedJsonContent = jsonContent.replaceAll(/"techniqueID": "t/, '"techniqueID": "T')

                    // Write the updated content back to the file
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
