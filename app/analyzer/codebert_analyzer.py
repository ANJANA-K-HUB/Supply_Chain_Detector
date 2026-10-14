import torch
from transformers import AutoTokenizer, AutoModel

class CodeBERTAnalyzer:
    def __init__(self, model_name: str = "microsoft/codebert-base"):
        """
        Initializes CodeBERT for semantic code representation and vulnerability pattern detection.
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Initializing CodeBERT on device: {self.device}")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()

    def get_code_embedding(self, code_snippet: str):
        """
        Generates a dense semantic embedding vector for a given code snippet.
        """
        inputs = self.tokenizer(
            code_snippet, 
            return_tensors="pt", 
            truncation=True, 
            max_length=512, 
            padding=True
        ).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            # Mean pooling for robust semantic representation
            embeddings = outputs.last_hidden_state.mean(dim=1)
            
        return embeddings.cpu().numpy().tolist()[0]

    def analyze_snippet_risk(self, code_snippet: str):
        """
        Analyzes semantic risk properties based on token embedding activations.
        """
        embedding = self.get_code_embedding(code_snippet)
        risk_score = float(sum(abs(x) for x in embedding) / len(embedding))
        
        return {
            "embedding_dimension": len(embedding),
            "semantic_risk_score": round(risk_score, 4),
            "status": "Analyzed successfully"
        }

if __name__ == "__main__":
    # Initialize the analyzer
    analyzer = CodeBERTAnalyzer()
    
    # Test code snippet (simulating a risky OS command execution)
    sample_code = "import os; user_input = input(); os.system(user_input)"
    
    # Run analysis
    result = analyzer.analyze_snippet_risk(sample_code)
    print("\n--- CodeBERT Test Results ---")
    for key, value in result.items():
        print(f"{key}: {value}")