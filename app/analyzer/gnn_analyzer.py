import torch
import torch.nn as nn
import torch.nn.functional as F

class SimpleGraphConvolution(nn.Module):
    """
    A lightweight Graph Convolutional layer for dependency network risk propagation.
    """
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.linear = nn.Linear(in_features, out_features)

    def forward(self, x, adjacency_matrix):
        # Message passing: aggregate neighbor features via adjacency matrix multiplication
        support = self.linear(x)
        out = torch.mm(adjacency_matrix, support)
        return F.relu(out)

class DependencyGNN(nn.Module):
    def __init__(self, num_features: int, hidden_dim: int = 16):
        super().__init__()
        self.gc1 = SimpleGraphConvolution(num_features, hidden_dim)
        self.gc2 = SimpleGraphConvolution(hidden_dim, 1) # Output a scalar risk propagation score

    def forward(self, x, adjacency_matrix):
        h = self.gc1(x, adjacency_matrix)
        out = torch.sigmoid(self.gc2(h, adjacency_matrix))
        return out

class GNNAnalyzer:
    def __init__(self, feature_dim: int = 4):
        """
        Initializes the GNN analyzer model for dependency graph risk evaluation.
        """
        self.model = DependencyGNN(num_features=feature_dim)
        self.model.eval()

    def evaluate_graph_risks(self, node_features: list, adjacency_matrix: list):
        """
        Evaluates cascading risk across the dependency graph network.
        
        Args:
            node_features: List of feature vectors for each node (e.g., [vuln_count, exists_on_pypi, release_count, codebert_score])
            adjacency_matrix: 2D list representing graph connections (edges)
        """
        x = torch.tensor(node_features, dtype=torch.float32)
        adj = torch.tensor(adjacency_matrix, dtype=torch.float32)
        
        with torch.no_grad():
            risk_predictions = self.model(x, adj)
            
        return {
            "propagated_risk_scores": risk_predictions.squeeze().tolist(),
            "status": "GNN structural analysis completed successfully"
        }

if __name__ == "__main__":
    # Test simulation with 3 dummy nodes (Project + 2 Dependencies)
    # Features: [vuln_count, pypi_status, release_count, codebert_score]
    dummy_features = [
        [0.0, 1.0, 10.0, 0.2],  # Project node
        [2.0, 1.0, 50.0, 0.8],  # Vulnerable dependency node
        [0.0, 1.0, 200.0, 0.1]  # Safe dependency node
    ]
    # Identity/Adjacency matrix representation
    dummy_adj = [
        [1.0, 1.0, 1.0],
        [1.0, 1.0, 0.0],
        [1.0, 0.0, 1.0]
    ]
    
    analyzer = GNNAnalyzer(feature_dim=4)
    res = analyzer.evaluate_graph_risks(dummy_features, dummy_adj)
    print("\n--- GNN Analyzer Test Results ---")
    for k, v in res.items():
        print(f"{k}: {v}")