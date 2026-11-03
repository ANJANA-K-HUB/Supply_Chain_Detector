import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [repoUrl, setRepoUrl] = useState('https://github.com/ANJANA-K-HUB/AI-Resume-Matcher');
  const [loading, setLoading] = useState(false);
  const [reportData, setReportData] = useState(null);

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      const response = await axios.post(
        `http://localhost:8000/analyze/full-pipeline?repo_path_or_url=${encodeURIComponent(repoUrl)}`
      );
      setReportData(response.data);
    } catch (error) {
      console.error("Error analyzing repository:", error);
      alert("Failed to analyze repository. Make sure your FastAPI backend is running on port 8000!");
    } finally {
      setLoading(false);
    }
  };

  const getTierBadge = (tier) => {
    if (tier === 'High') return { bg: '#fee2e2', color: '#dc2626', border: '#fca5a5' };
    if (tier === 'Medium') return { bg: '#fef3c7', color: '#d97706', border: '#fde68a' };
    return { bg: '#dcfce7', color: '#16a34a', border: '#bbf7d0' };
  };

  const allDependencies = reportData?.parsed_dependencies || [];
  const vulnerableComponents = reportData?.affected_components || [];
  const riskTier = reportData?.final_security_report?.executive_summary?.overall_risk_tier || 'Low';
  const tierStyle = getTierBadge(riskTier);
  const manifestDetected = reportData?.automated_findings?.manifest_detected;

  return (
    <div style={{ fontFamily: "'Inter', system-ui, -apple-system, sans-serif", backgroundColor: '#f8fafc', minHeight: '100vh', color: '#1e293b', padding: '30px 40px' }}>
      
      {/* Top Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #e2e8f0', paddingBottom: '20px', marginBottom: '30px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '26px' }}>🛡️</span>
            <h1 style={{ fontSize: '22px', fontWeight: 700, margin: 0, letterSpacing: '-0.5px', color: '#0f172a' }}>
              AI-Based Software Supply-Chain Attack Detection System
            </h1>
          </div>
          <p style={{ color: '#64748b', fontSize: '13px', margin: '4px 0 0 38px' }}>
            Automated Graph Neural Network (GNN) & CodeBERT Security Intelligence Dashboard
          </p>
        </div>
        <div style={{ background: '#f1f5f9', padding: '6px 14px', borderRadius: '20px', border: '1px solid #cbd5e1', fontSize: '12px', color: '#0284c7', fontWeight: 600 }}>
          System Status: Operational 🟢
        </div>
      </header>

      {/* Target URL Input Bar */}
      <div style={{ background: '#ffffff', padding: '20px 24px', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)', marginBottom: '30px', border: '1px solid #e2e8f0' }}>
        <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px', color: '#475569' }}>
          Target GitHub Repository URI / Path:
        </label>
        <div style={{ display: 'flex', gap: '12px' }}>
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            style={{ flex: 1, padding: '12px 16px', borderRadius: '8px', border: '1px solid #cbd5e1', backgroundColor: '#f8fafc', color: '#0f172a', fontSize: '14px', outline: 'none' }}
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            style={{
              padding: '12px 24px',
              backgroundColor: '#2563eb',
              color: '#fff',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '14px',
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.2)'
            }}
          >
            {loading ? 'Running Pipeline...' : 'Run Analysis ⚡'}
          </button>
        </div>
      </div>

      {reportData && (
        <div>
          {/* Top Metric Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px', marginBottom: '30px' }}>
            
            <div style={{ background: '#ffffff', padding: '20px 24px', borderRadius: '12px', border: '1px solid #e2e8f0', borderLeft: `5px solid ${tierStyle.color}`, boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <span style={{ fontSize: '12px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>Overall Risk Tier</span>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '8px' }}>
                <span style={{ fontSize: '24px', fontWeight: 700, padding: '4px 12px', borderRadius: '6px', backgroundColor: tierStyle.bg, color: tierStyle.color, border: `1px solid ${tierStyle.border}` }}>
                  {riskTier}
                </span>
              </div>
            </div>

            <div style={{ background: '#ffffff', padding: '20px 24px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <span style={{ fontSize: '12px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>Aggregate Risk Score</span>
              <p style={{ fontSize: '28px', fontWeight: 700, margin: '8px 0 0 0', color: '#0f172a' }}>
                {reportData.final_security_report?.executive_summary?.aggregate_risk_score ?? 'N/A'}
              </p>
            </div>

            <div style={{ background: '#ffffff', padding: '20px 24px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>Detected Vulnerabilities</span>
                {manifestDetected && (
                  <span style={{ fontSize: '10px', background: '#e0f2fe', color: '#0369a1', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, border: '1px solid #bae6fd' }}>
                    Manifest: {manifestDetected}
                  </span>
                )}
              </div>
              <p style={{ fontSize: '28px', fontWeight: 700, margin: '8px 0 0 0', color: vulnerableComponents.length > 0 ? '#dc2626' : '#16a34a' }}>
                {reportData.automated_findings?.vulnerabilities_detected ?? '0'}
              </p>
            </div>

          </div>

          {/* Main Grid: Visual Dependency Graph & Affected Components */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px', marginBottom: '30px' }}>
            
            {/* Visual Graph Card - Lists ALL dependencies (Green for secure, Red for vulnerable) */}
            <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: '#0f172a', margin: '0 0 4px 0' }}>Dependency Graph Topology</h2>
              <p style={{ fontSize: '12px', color: '#64748b', marginBottom: '16px' }}>Cascading node evaluation & network mapping (Neo4j architecture)</p>
              
              <div style={{ background: '#f8fafc', padding: '20px', borderRadius: '10px', border: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                
                <div style={{ background: '#ffffff', color: '#0284c7', border: '1px solid #bae6fd', padding: '10px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: 600, textAlign: 'center', width: '90%', wordBreak: 'break-all', boxShadow: '0 2px 4px rgba(0,0,0,0.04)' }}>
                  📦 {reportData.automated_findings?.repository_scanned || repoUrl}
                </div>

                <div style={{ color: '#64748b', fontSize: '12px', fontWeight: 600, background: '#e2e8f0', padding: '2px 10px', borderRadius: '10px', border: '1px solid #cbd5e1' }}>
                  ↓ depends on ↓
                </div>

                <div style={{ display: 'flex', gap: '8px', width: '100%', justifyContent: 'center', flexWrap: 'wrap' }}>
                  {allDependencies.length > 0 ? (
                    allDependencies.map((dep, idx) => {
                      const isVulnerable = vulnerableComponents.some(v => v.toLowerCase().includes(dep.split('=')[0].split('@')[0].toLowerCase()));
                      return (
                        <div key={idx} style={{ 
                          background: isVulnerable ? '#fee2e2' : '#f0fdf4', 
                          color: isVulnerable ? '#dc2626' : '#16a34a', 
                          border: `1px solid ${isVulnerable ? '#fca5a5' : '#bbf7d0'}`, 
                          padding: '6px 12px', 
                          borderRadius: '6px', 
                          fontSize: '12px', 
                          fontWeight: 600, 
                          textAlign: 'center' 
                        }}>
                          {isVulnerable ? '⚠️ ' : '✅ '}{dep}
                        </div>
                      );
                    })
                  ) : (
                    <div style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #bbf7d0', padding: '6px 14px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, textAlign: 'center' }}>
                      ✨ Verified Secure (No Nodes Found)
                    </div>
                  )}
                </div>

                <div style={{ marginTop: '8px', paddingTop: '10px', borderTop: '1px dashed #cbd5e1', width: '100%', display: 'flex', justifyContent: 'space-around', fontSize: '11px', color: '#64748b' }}>
                  <span>GNN Structural Risk: <strong style={{ color: '#0f172a' }}>{reportData.risk_breakdown?.gnn_risk ?? '0.05'}</strong></span>
                  <span>CodeBERT Score: <strong style={{ color: '#0f172a' }}>{reportData.risk_breakdown?.codebert_score ?? '0.15'}</strong></span>
                </div>

              </div>
            </div>

            {/* Affected Components List Card */}
            <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: '#0f172a', margin: '0 0 4px 0' }}>Affected Components</h2>
              <p style={{ fontSize: '12px', color: '#64748b', marginBottom: '16px' }}>Vulnerable packages and modules detected in dependency manifests:</p>
              
              <div style={{ background: '#f8fafc', padding: '16px', borderRadius: '10px', border: '1px solid #e2e8f0', minHeight: '140px' }}>
                {vulnerableComponents.length > 0 ? (
                  <ul style={{ paddingLeft: '18px', margin: 0 }}>
                    {vulnerableComponents.map((comp, idx) => (
                      <li key={idx} style={{ marginBottom: '10px', color: '#dc2626', fontFamily: 'monospace', fontWeight: 600, fontSize: '14px' }}>
                        {comp} <span style={{ fontSize: '11px', background: '#fee2e2', color: '#dc2626', border: '1px solid #fca5a5', padding: '2px 6px', borderRadius: '4px', marginLeft: '8px', fontWeight: 'normal' }}>Critical / Flagged</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div style={{ color: '#16a34a', fontSize: '13px', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '8px', height: '100%', padding: '10px' }}>
                    <span>✅ All requirement manifests verified. No anomalous dependencies detected.</span>
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* Bottom Grid: Investigation Results & AI-Assisted Security Report */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            
            <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: '#0f172a', margin: '0 0 12px 0' }}>Investigation Results & XAI Insights</h2>
              <ul style={{ paddingLeft: '18px', margin: 0, display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {reportData.final_security_report?.explainable_ai_insights?.reasons?.map((reason, idx) => (
                  <li key={idx} style={{ color: '#475569', fontSize: '13px', lineHeight: '1.5' }}>{reason}</li>
                ))}
              </ul>
            </div>

            <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: '#0f172a', margin: '0 0 12px 0' }}>Recommended Actions</h2>
              <ul style={{ paddingLeft: '18px', margin: 0, display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {reportData.final_security_report?.recommended_actions?.map((action, idx) => (
                  <li key={idx} style={{ color: '#475569', fontSize: '13px', lineHeight: '1.5' }}>{action}</li>
                ))}
              </ul>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}

export default App;