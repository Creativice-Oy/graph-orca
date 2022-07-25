import { OrcaAlert } from '../../types';
import {
  createDirectRelationship,
  createIntegrationEntity,
  Entity,
  Relationship,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';
import { Entities } from '../constants';

export function createAlertFindingEntity(
  alert: OrcaAlert,
  baseUrl: string,
): Entity {
  return createIntegrationEntity({
    entityData: {
      source: alert,
      assign: {
        _type: Entities.ALERT._type,
        _class: Entities.ALERT._class,
        _key: `${alert.asset_unique_id}:${alert.state.alert_id}`,
        name: alert.description,
        severity: alert.state.severity,
        numericSeverity: alert.state.score,
        open: alert.state.status === 'open',
        category: alert.category,
        summary: alert.type_string,
        description: alert.details,
        recommendation: alert.recommendation,
        typeKey: alert.type_key,
        ruleId: alert.rule_id,
        groupType: alert.group_type,
        groupName: alert.group_name,
        groupId: alert.group_unique_id,
        clusterType: alert.cluster_type,
        clusterName: alert.cluster_name,
        clusterId: alert.cluster_unique_id,
        subjectType: alert.subject_type,
        assetId: alert.asset_unique_id,
        assetCategory: alert.asset_category,
        assetType: alert.asset_type,
        assetName: alert.asset_name,
        accountName: alert.account_name,
        cloudVendorId: alert.cloud_vendor_id,
        cloudProvider: alert.cloud_provider,
        cloudProviderId: alert.cloud_provider_id,
        cloudAccountId: alert.cloud_account_id,
        assetDistributionName: alert.asset_distribution_name,
        assetDistributionVersion: alert.asset_distribution_version,
        assetDistributionMajorVersion: alert.asset_distribution_major_version,
        organizationId: alert.organization_id,
        organizationName: alert.organization_name,
        vmId: alert.vm_id,
      },
    },
  });
}

export function createAccountAlertRelationship(
  account: Entity,
  alert: Entity,
): Relationship {
  return createDirectRelationship({
    _class: RelationshipClass.HAS,
    from: account,
    to: alert,
  });
}

export function createAlertFindingRelationship(
  alert: Entity,
  finding: Entity,
): Relationship {
  return createDirectRelationship({
    _class: RelationshipClass.HAS,
    from: alert,
    to: finding,
  });
}
