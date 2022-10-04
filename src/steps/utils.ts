import { OrcaAlertCVE, OrcaCVE } from '../types';

export function buildFindingKey(assetId: string, cveId: string) {
  return `${assetId}:${cveId}`;
}

export function extractCVSS(cve: OrcaCVE | OrcaAlertCVE): {
  cvssScore: number;
  cvssVector: string;
  cvssSeverity: string;
} {
  return cve.nvd.cvss3_score
    ? {
        cvssScore: cve.nvd.cvss3_score,
        cvssVector: cve.nvd.cvss3_vector?.toUpperCase(),
        cvssSeverity: cve.nvd.cvss3_severity?.toLowerCase(),
      }
    : {
        cvssScore: cve.nvd.cvss2_score,
        cvssVector: cve.nvd.cvss2_vector?.toUpperCase(),
        cvssSeverity: cve.nvd.cvss2_severity?.toLowerCase(),
      };
}
