import {
  createIntegrationEntity,
  createDirectRelationship,
  Entity,
  RelationshipClass,
  Relationship,
  createMappedRelationship,
  RelationshipDirection,
} from '@jupiterone/integration-sdk-core';

import { Entities } from '../constants';
import { OrcaCVE } from '../../types';
import { buildFindingKey, extractCVSS } from '../utils';

export function createFindingEntity(cve: OrcaCVE): Entity {
  const { cvssScore, cvssVector, cvssSeverity } = extractCVSS(cve);
  const fixAvailable = cve.fix_available_state.toLowerCase() === 'yes';

  return createIntegrationEntity({
    entityData: {
      source: cve,
      assign: {
        _type: Entities.FINDING._type,
        _class: Entities.FINDING._class,
        _key: buildFindingKey(cve.asset_unique_id, cve.cve_id),
        category: cve.labels ? cve.labels[0] : 'unknown',
        name: cve.cve_id,
        score: cvssScore,
        severity: cvssSeverity ?? 'unknown',
        vector: cvssVector,
        cvss3Score: cve.nvd?.cvss3_score,
        cvss2Score: cve.nvd?.cvss2_score,
        orcaScore: cve.score,
        orcaSeverity: cve.severity?.toLowerCase(),
        numericSeverity: cvssScore ?? 0,
        open: !fixAvailable,
        affectedPackages: cve.affected_packages,
        packages: [
          ...new Set((cve.packages ?? []).map((pkg) => pkg.package_name)),
        ],
        references: cve.vendor_source_link
          ? [cve.vendor_source_link]
          : undefined,
        fixable: fixAvailable === true,
        groupType: cve.group_type,
        clusterType: cve.cluster_type,
        type: cve.type,
        assetCategory: cve.asset_category,
        assetType: cve.asset_type,
        cloudVendorId: cve.cloud_vendor_id,
        assetDistributionName: cve.asset_distribution_name,
        cloudProvider: cve.cloud_provider,
        assetVendorId: cve.asset_vendor_id,
        vmId: cve.vm_id,
        assetLabels: cve.asset_labels,
      },
    },
  });
}

export function createAssetFindingRelationship(
  asset: Entity,
  finding: Entity,
): Relationship {
  return createDirectRelationship({
    _class: RelationshipClass.HAS,
    from: asset,
    to: finding,
  });
}

export function createAccountFindingRelationship(
  account: Entity,
  finding: Entity,
): Relationship {
  return createDirectRelationship({
    _class: RelationshipClass.HAS,
    from: account,
    to: finding,
  });
}

export function createFindingCveRelationship(
  finding: Entity,
  cve: OrcaCVE,
): Relationship {
  const { cvssScore, cvssVector, cvssSeverity } = extractCVSS(cve);
  const cveIdDisplay = cve.cve_id.toUpperCase();

  return createMappedRelationship({
    _class: RelationshipClass.IS,
    _type: 'orca_finding_is_cve',
    _mapping: {
      sourceEntityKey: finding._key,
      relationshipDirection: RelationshipDirection.FORWARD,
      skipTargetCreation: false,
      targetFilterKeys: [['_type', '_key']],
      targetEntity: {
        _key: cve.cve_id.toLowerCase(),
        _type: 'cve',
        id: cve.cve_id,
        score: cvssScore ?? 0,
        vector: cvssVector,
        name: cveIdDisplay,
        displayName: cveIdDisplay,
        severity: cvssSeverity,
        references: [`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`],
        webLink: `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`,
      },
    },
  });
}
