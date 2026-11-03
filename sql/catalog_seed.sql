USE saip;

-- Template AI services. github.com / microsoft.com / google.com are deliberately NOT listed:
-- they carry large non-AI traffic. Only AI-specific hostnames.
INSERT IGNORE INTO catalog_services (id, service_name, provider, primary_domain, category, description, data_class, training_exposure, vendor_risk, identity_risk) VALUES
 (1,'ChatGPT','OpenAI','chatgpt.com','Generative AI','OpenAI conversational assistant','Confidential',70,60,75),
 (2,'Claude','Anthropic','claude.ai','Generative AI','Anthropic conversational assistant','Internal',30,30,40),
 (3,'Google Gemini','Google','gemini.google.com','Generative AI','Google Gemini web app','Internal',35,25,30),
 (4,'Microsoft Copilot','Microsoft','copilot.microsoft.com','Generative AI','Microsoft Copilot web experience','Internal',10,15,10),
 (5,'Perplexity','Perplexity AI','perplexity.ai','AI Search','AI answer engine','Restricted / PII',65,60,70),
 (6,'GitHub Copilot','GitHub / Microsoft','api.githubcopilot.com','Coding Assistant','Copilot endpoints only (not github.com)','Internal',20,20,25),
 (7,'DeepSeek','DeepSeek','chat.deepseek.com','Generative AI','DeepSeek chat','Confidential',85,90,80),
 (8,'Midjourney','Midjourney','midjourney.com','Image Generation','Image generation service','Public',60,50,60),
 (9,'Hugging Face Hub','Hugging Face','huggingface.co','Model Hub','Open model weights and tokenizers','Internal',15,20,20);

INSERT IGNORE INTO catalog_domains (catalog_service_id, domain) VALUES
 (1,'chatgpt.com'),(1,'chat.openai.com'),(1,'api.openai.com'),
 (2,'claude.ai'),(2,'api.anthropic.com'),
 (3,'gemini.google.com'),(3,'generativelanguage.googleapis.com'),
 (4,'copilot.microsoft.com'),
 (5,'perplexity.ai'),
 (6,'api.githubcopilot.com'),(6,'copilot-proxy.githubusercontent.com'),
 (7,'chat.deepseek.com'),(7,'api.deepseek.com'),
 (8,'midjourney.com'),
 (9,'huggingface.co');

INSERT IGNORE INTO catalog_controls (control_code, domain, name, description, sort_order) VALUES
 ('A.2-1','A.2 Policies','AI Acceptable Use Policy','Approved AI policy defining sanctioned vs unapproved AI tools published and acknowledged.',10),
 ('A.3-1','A.3 Organization','AI Governance & Accountability','Designated AI compliance owner and clear roles for tool adoption established.',20),
 ('A.4-1','A.4 AI Inventory','Continuous AI Asset Register (cl. 8.2)','Documented ledger of all AI systems to eliminate uncatalogued Shadow AI.',30),
 ('A.5-1','A.5 Risk Assessment','AI Risk Assessment Methodology','Standardised 0-100 scoring based on data sensitivity and usage exposure.',40),
 ('A.5-2','A.5 Risk Assessment','Traceable Risk Treatment Records','Documented risk acceptance, mitigation or blocking per AI system.',50),
 ('A.6-1','A.6 Lifecycle','Pre-Deployment AI Vetting','Structured request queue before tools are sanctioned.',60),
 ('A.6-2','A.6 Lifecycle','Active Technical Enforcement','Blocklist feed generated for unapproved endpoints and loaded into resolvers/firewalls.',70),
 ('A.7-1','A.7 Data for AI','Data Classification Guardrails','Data categorisation (Confidential, PII, Public) applied to AI services.',80),
 ('A.7-2','A.7 Data for AI','Non-Training Verification','Verification that third-party AI vendors do not train models on company inputs.',90),
 ('A.8-1','A.8 Transparency','User Notification & Explainability','Employees informed when engaging with AI-generated outputs and assistants.',100),
 ('A.9-1','A.9 Security','Endpoint Telemetry Coverage','Endpoint monitoring detects AI service access across managed workstations.',110),
 ('A.9-2','A.9 Security','Incident Response for Shadow AI','Formal security incident workflow for unauthorised Shadow AI events.',120),
 ('A.10-1','A.10 Vendor Relations','AI Vendor Security Review','SOC 2 / ISO 27001 evaluation for all third-party commercial AI vendors.',130),
 ('A.10-2','A.10 Vendor Relations','Data Processing Agreements (DPA)','Executed DPAs with AI providers covering GDPR Art. 30 requirements.',140);

INSERT IGNORE INTO catalog_policies (name, policy_type, status, description) VALUES
 ('Default Prohibit on Shadow AI','Zero-Trust Quarantine','Enforced','Any AI service without explicit approval is treated as Shadow AI and flagged for triage.'),
 ('Sanctioned Enterprise Only with SSO','Approved Baseline','Draft','Approved AI tools must use company SSO and have no vendor training on company data.'),
 ('Proprietary Source Code Egress Guard','Data Loss Prevention','Draft','Policy intent: no proprietary source code or key material to public AI endpoints. Technical enforcement is outside this platform (DLP/proxy).');
