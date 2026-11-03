# AI-Based Software Supply-Chain Attack Detection System

An end-to-end AI-powered security analysis dashboard designed to detect potential software supply-chain vulnerabilities in GitHub repositories. The system analyzes multi-ecosystem dependency trees (Python and Node.js), performs CodeBERT-based semantic analysis and Graph Neural Network (GNN)-based structural risk assessment, and stores dependency relationships in a local Neo4j graph database.

## 📌 Architecture Overview

| Component | Technology | URL / Description |
|---|---|---|
| Frontend | React.js | `http://localhost:3000` |
| Backend | FastAPI + Uvicorn | `http://127.0.0.1:8000` |
| Database | Neo4j Graph Database | `neo4j://127.0.0.1:7687` |
| AI/ML Engine | PyTorch, Transformers (CodeBERT), NetworkX | Semantic and graph-based risk analysis |

## ⚙️ Prerequisites

Ensure the following tools are installed on your system before proceeding:

1. **Python 3.10 or higher**
2. **Node.js (v16 or higher) and npm**
3. **Neo4j Desktop** or **Neo4j Community Server**
4. **Git**

## 🛠️ Installation and Setup

Follow these steps to configure and run the project locally.

### 1. Database Configuration (Neo4j)

1. Open **Neo4j Desktop** and create a new project.
2. Create a new database instance.
3. Configure the database connection using the following details:

   - **URI:** `neo4j://127.0.0.1:7687`
   - **Username:** `neo4j`
   - **Password:** Use the password configured for your local Neo4j database.

4. Start the database instance.
5. Ensure the database status is **Active / Running**.

> **Note:** Configure the Neo4j credentials in your backend environment variables or configuration file. Avoid hardcoding database passwords in source code.

### 2. Backend Setup (FastAPI)

**Step 1: Navigate to the project directory**

```bash
cd Supply_chain_detector
```

**Step 2: Create a virtual environment**

Windows:

```bash
python -m venv venv
```

Mac/Linux:

```bash
python3 -m venv venv
```

**Step 3: Activate the virtual environment**

Windows:

```bash
venv\Scripts\activate
```

Mac/Linux:

```bash
source venv/bin/activate
```

**Step 4: Install Python dependencies**

```bash
pip install -r requirements.txt
```

**Step 5: Start the FastAPI backend server**

```bash
uvicorn app.main:app --reload
```

The backend will be available at:

- **API Base URL:** http://127.0.0.1:8000
- **Interactive API Documentation:** http://127.0.0.1:8000/docs

### 3. Frontend Setup (React Dashboard)

Open a new terminal window.

**Step 1: Navigate to the frontend directory**

```bash
cd Supply_chain_detector/frontend
```

**Step 2: Install Node.js dependencies**

```bash
npm install
```

**Step 3: Start the React development server**

```bash
npm start
```

The React dashboard will be available at:

http://localhost:3000

## 🚀 How to Run an Analysis

Follow these steps to analyze a GitHub repository:

1. Ensure that **Neo4j**, the **FastAPI backend**, and the **React frontend** are running.
2. Open your browser and navigate to http://localhost:3000.
3. Enter a valid GitHub repository URL containing either a `requirements.txt` or `package.json` dependency manifest.

   Example:

   ```text
   https://github.com/ANJANA-K-HUB/iris_streamlit_app
   ```

4. Click the **Run Analysis** button.
5. Wait for the repository analysis pipeline to complete.
6. View the generated security analysis results on the dashboard.

### 📊 Analysis Results

The dashboard provides the following information:

- **Overall Risk Tier and Aggregate Score:** Displays the overall repository risk assessment based on CodeBERT semantic analysis and GNN structural analysis.
- **Dependency Graph Visualization:** Displays dependency relationships and highlights secure components in green and vulnerable components in red, according to the analysis results.
- **CodeBERT Semantic Analysis:** Evaluates semantic information to identify potentially suspicious dependency-related patterns.
- **GNN Structural Risk Assessment:** Analyzes dependency relationships and graph topology to identify potentially risky components.
- **Neo4j Database Synchronization:** Automatically stores dependency nodes and `HAS_DEPENDENCY` relationships in the local Neo4j database.

You can inspect the stored graph data using:

**Neo4j Browser:** http://localhost:7474

## 🧪 Quick Test Repositories

Use the following GitHub repositories to test the application:

| Repository | Description | Manifest |
|---|---|---|
| [iris_streamlit_app](https://github.com/ANJANA-K-HUB/iris_streamlit_app) | Python repository with an unpinned dependency manifest | `requirements.txt` |
| [twitter-sentiment-app](https://github.com/ANJANA-K-HUB/twitter-sentiment-app) | Python repository with a pinned dependency manifest | `requirements.txt` |

## 📁 Project Folder Structure

```text
Supply_chain_detector/
│
├── app/
│   ├── analyzer/
│   │   └── AI/ML CodeBERT and GNN analysis modules
│   │
│   ├── database/
│   │   └── Neo4j Cypher queries and database loader routines
│   │
│   └── main.py
│       └── FastAPI REST endpoints and pipeline orchestrator
│
├── frontend/
│   └── React dashboard components and styling
│
├── requirements.txt
│   └── Python dependency manifest
│
└── README.md
    └── Project documentation
```

## 🧠 Technologies Used

- **Frontend:** React.js
- **Backend:** Python, FastAPI, Uvicorn
- **Machine Learning:** PyTorch
- **Pre-trained Language Model:** CodeBERT
- **Graph Analysis:** NetworkX and Graph Neural Networks (GNN)
- **Database:** Neo4j
- **Dependency Ecosystems:** Python and Node.js

## 🔒 Security Considerations

- Keep database credentials in environment variables rather than committing them to GitHub.
- Do not expose Neo4j credentials or API secrets in frontend code.
- Analyze repositories in an isolated environment when possible.
- Treat repository contents and dependency manifests as untrusted input.
- Keep Python and Node.js dependencies updated.

## 👩‍💻 Author

**Anjana K**

GitHub: [ANJANA-K-HUB](https://github.com/ANJANA-K-HUB)

---

⭐ If you find this project interesting, consider giving the repository a star on GitHub!
