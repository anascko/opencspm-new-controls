# frozen_string_literal: true

require 'yaml'
require 'date'
require 'pp'

config_file = YAML.load(File.read(File.expand_path(File.dirname(__FILE__) + '/config.yaml')))
control_pack = config_file['id']
titles = Hash[config_file['controls'].map { |control| [control['id'], control['title']] }]

# GCP
control_id = 'rule-gcp-6'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_IDENTITY)-[r:HAS_IAMROLE]-(p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    WHERE r.role_name = 'roles/iam.serviceAccountUser' OR
          r.role_name = 'roles/iam.serviceAccountTokenCreator'
    RETURN c.name as name, r.role_name as role_name
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      describe identity.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have iam.serviceAccountUser or iam.serviceAccountTokenCreator bound at the project level' do
          expect(identity.role_name).not_to eq('roles/iam.serviceAccountUser')
          expect(identity.role_name).not_to eq('roles/iam.serviceAccountTokenCreator')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have iam.serviceAccountUser or iam.serviceAccountTokenCreator bound at the project level' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-14'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (s:GCP_COMPUTE_SUBNETWORK)
    RETURN s.name as name,
           s.resource_data_logConfig_enable as flow_logging,
           s.resource_data_logConfig_flowSampling as flow_sampling,
           s.resource_data_logConfig_metadata as metadata
  )
  subnets = graphdb.query(q).mapped_results
  if subnets.length > 0
    subnets.each do |subnet|
      describe subnet.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have full VPC Flow logging enabled' do
          expect(subnet.flow_logging).to eq('true')
          expect(subnet.flow_sampling).to eq('1')
          expect(subnet.metadata).to eq('INCLUDE_ALL_METADATA')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have full VPC Flow logging enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-15'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(f:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS", resource_data_disabled: "false" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL)
    WHERE ((rule.from_port <= 22 AND 22 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    RETURN DISTINCT f.name as firewall_name
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not allow TCP/22 from 0.0.0.0/0' do
          expect(fw.firewall_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not allow TCP/22 from 0.0.0.0/0' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-17'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    OPTIONAL MATCH (i)-[:HAS_NETWORKACCESSCONFIG]->(n:GCP_COMPUTE_NETWORKACCESSCONFIG)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    return i.name as name, n.type as network_type
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have a private IP' do
          expect(instance.network_type).not_to eq('ONE_TO_ONE_NAT')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a private IP' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-18'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (v:GCP_COMPUTE_NETWORK)
    WHERE NOT v.resource_data_name IS NULL
    RETURN v.name as vpc_name, v.resource_data_name as display_name
  )
  vpcs = graphdb.query(q).mapped_results
  if vpcs.length > 0
    vpcs.each do |vpc|
      describe vpc.vpc_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be a default VPC' do
          expect(vpc.display_name).not_to eq('default')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be a default VPC' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-19'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sa:GCP_IAM_SERVICEACCOUNTKEY)
    WHERE sa.resource_data_keyType = "USER_MANAGED"
      and NOT sa.resource_data_validAfterTime IS NULL
    RETURN sa.name as sa_name, sa.resource_data_validAfterTime as start_time
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      describe sa.sa_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be older than 90 days' do
          days_old = (DateTime.now - DateTime.parse(sa.start_time)).to_i
          expect(days_old).to be <= 90
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be older than 90 days' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-20'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
   MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
   OPTIONAL MATCH (project)-[r:HAS_AUDITCONFIG]->(svc:GCP_CLOUDRESOURCEMANAGER_PROJECTAUDITSERVICE)
   WHERE svc.name = 'allServices'
   RETURN project.name as project_name, project.resource_data_name as display_name, r.log_type as log_type, r.exempted_members as exempted_members
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    configs = projects.group_by { |r| "#{r[:project_name]}[#{r[:display_name]}]" }.map do |np, configs|
      log_types = configs.group_by { |s| s[:log_type] }.map { |k, _v| k }.sort
      exempted_members = configs.group_by { |s| s[:exempted_members] }.map { |k, _v| k }.compact
      [np, log_types, exempted_members]
    end
    configs.each do |config|
      describe config[0], control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have audit logging configured' do
          expect(config[1]).to eq(%w[1 2 3])
          expect(config[2]).to eq([])
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have audit logging configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-22'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_SQLADMIN_INSTANCE)
    RETURN instance.name as name, instance.resource_data_settings_ipConfiguration_ipv4Enabled as public
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be public' do
          expect(instance.public).to eq('false')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be public' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-23'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_SQLADMIN_INSTANCE)
    RETURN instance.name as name, instance.resource_data_settings_ipConfiguration_requireSsl as requires_ssl
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should require SSL' do
          expect(instance.requires_ssl).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should require SSL' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-26'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(f:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS", resource_data_disabled: "false" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL)
    WHERE ((rule.from_port <= 3389 AND 3389 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    RETURN DISTINCT f.name as firewall_name
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not allow TCP/3389 from 0.0.0.0/0' do
          expect(fw.firewall_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not allow TCP/3389 from 0.0.0.0/0' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-33'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (httpsproxy:GCP_COMPUTE_TARGETHTTPSPROXY)
    OPTIONAL MATCH (sslproxy:GCP_COMPUTE_TARGETSSLPROXY)
    RETURN httpsproxy.name as https_name, httpsproxy.resource_data_sslPolicy as https_sslpolicy, sslproxy.name as ssl_name, sslproxy.resource_data_sslPolicy as ssl_sslpolicy
  )
  proxies = graphdb.query(q).mapped_results
  if proxies.length > 0
    proxies.each do |proxy|
      proxy_name = proxy.https_name || proxy.ssl_name
      proxy_policy = proxy.https_sslpolicy || proxy.ssl_sslPolicy
      describe proxy_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have an SSL Policy configured' do
          expect(proxy_policy).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have an SSL Policy configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-38'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_networkPolicy_enabled as network_policy
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Network Policy configured' do
          expect(cluster.network_policy).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Network Policy configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-39'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    OPTIONAL MATCH (c:GCP_CONTAINER_CLUSTER)-[:HAS_MASTERAUTHORIZEDNETWORK]->(n:GCP_CONTAINER_MASTERAUTHORIZEDNETWORK)
    WHERE n.cidr_block = '0.0.0.0/0'
    RETURN c.name as name, c.resource_data_masterAuthorizedNetworksConfig_enabled as authorized_networks_enabled, n.cidr_block as any_ip
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should restrict access to the API' do
          expect(cluster.authorized_networks_enabled).to eq('true')
          expect(cluster.any_ip).not_to eq('0.0.0.0/0')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should restrict access to the API' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-40'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_workloadIdentityConfig_workloadPool as wi
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Workload Identity configured' do
          expect(cluster.wi).to include('svc.id.goog')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Workload Identity configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-41'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)-[r:HAS_SERVICEACCOUNT]->(gi:GCP_IDENTITY)
    RETURN c.name as name, gi.resource_data_email as sa_name
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have the default ServiceAccount attached' do
          expect(nodepool.sa_name).not_to include('-compute@developer.gserviceaccount.com')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have the default ServiceAccount attached' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-42'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_shieldedNodes_enabled as shielded_nodes
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Shielded Nodes configured' do
          expect(cluster.shielded_nodes).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Shielded Nodes configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-44'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_privateClusterConfig_privateEndpoint as private_endpoint
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have a Private Master Endpoint configured' do
          expect(cluster.private_endpoint).not_to be(nil)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a Private Master Endpoint configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-47'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_networkConfig_enableIntraNodeVisibility as intranode_visibility
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have IntraNode Visibility configured' do
          expect(cluster.intranode_visibility).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have IntraNode Visibility configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-48'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_loggingService as logging
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have GCP Logging configured' do
          expect(cluster.logging).to eq('logging.googleapis.com/kubernetes')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have GCP Logging configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-50'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.config_imageType as os
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should use COS or COS_CONTAINERD' do
          expect(nodepool.os).to match(/^COS.*/i)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should use COS or COS_CONTAINERD' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-52'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.management_autoRepair as autorepair
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have autorepair enabled' do
          expect(nodepool.autorepair).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have autorepair enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-53'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.management_autoUpgrade as autoupgrade
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have autoupgrade enabled' do
          expect(nodepool.autoupgrade).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have autoupgrade enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-55'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_ipAllocationPolicy_useIpAliases AS subnet_range_enabled
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Subnet IP Alias Ranges configured' do
          expect(cluster.subnet_range_enabled).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Subnet IP Alias Ranges configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-56'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_legacyAbac as abac
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have legacy Abac configured' do
          expect(cluster.abac).to be(nil)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have legacy Abac configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-59'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_SQLADMIN_INSTANCE)
    WHERE instance.resource_data_instanceType <> 'READ_REPLICA_INSTANCE'
    RETURN instance.name as instance_name, instance.resource_data_settings_backupConfiguration_enabled as backups, instance.resource_data_settings_backupConfiguration_binaryLogEnabled as binlog_enabled
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have automatic backups configured' do
          expect(instance.backups).to eq('true')
          expect(instance.binlog_enabled).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have automatic backups configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-60'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_IDENTITY { member_type: 'serviceAccount' })-[r:HAS_IAMROLE]-(p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    WHERE c.name ENDS WITH '-compute@developer.gserviceaccount.com'
    RETURN c.name as name, r.role_name as role_name
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    records = sas.group_by { |r| r[:name] }.map do |id, roles|
      editor = (roles.select { |k, _v| (k['role_name'] == 'roles/editor') }.length > 0) || false
      [id, editor]
    end
    records.each do |sa|
      describe sa[0], control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have Editor bound to the default service account' do
          expect(sa[1]).to eq(false)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have Editor bound to the default service account' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-61'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_databaseEncryption_state as encryption_state
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should encrypt secrets at rest in Etcd' do
          expect(cluster.encryption_state).to eq('ENCRYPTED')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should encrypt secrets at rest in Etcd' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-62'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sak:GCP_IAM_SERVICEACCOUNTKEY)
    WHERE sak.resource_data_keyType = "USER_MANAGED"
    RETURN DISTINCT sak.resource_parent as sa_id
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      sa_id = sa.sa_id.gsub(%r{^//}, '')
      describe sa_id, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have user-managed keys' do
          expect(sa_id).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have user-managed keys' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-63'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gi:GCP_IDENTITY)
    WHERE gi.member_name ENDS WITH '.iam.gserviceaccount.com'
    OPTIONAL MATCH (resource)<-[ir1:HAS_IAMROLE]-(gi)
    WHERE (ir1.role_name = "roles/owner"
         OR ir1.role_name = "roles/editor"
         OR ir1.role_name CONTAINS 'Admin'
         OR ir1.role_name CONTAINS 'admin'
      )
      AND gi.member_name ENDS WITH '.iam.gserviceaccount.com'
    RETURN DISTINCT gi.name as identity_name, ir1.role_name as role_name, resource.name as resource_name
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      describe "#{identity.identity_name}: #{identity.role_name}->#{identity.resource_name}",
               control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be bound to admin, editor, or owner roles' do
          expect(identity.resource_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be bound to admin, editor, or owner roles' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-64'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gi:GCP_IDENTITY)-[ir1:HAS_IAMROLE]->(resource)
    MATCH (gi)-[ir2:HAS_IAMROLE]->(resource)
    WHERE ir1.role_name = "roles/iam.serviceAccountUser"
      AND ir2.role_name = "roles/iam.serviceAccountAdmin"
    RETURN DISTINCT gi.name as identity_name, resource.name as resource_name
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      describe "#{identity.identity_name} -> #{identity.resource_name}", control_pack: control_pack,
                                                                         control_id: control_id, "#{control_id}": true do
        it 'should not have iam admin and serviceaccountuser to the same resource' do
          expect(identity.resource_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have iam admin and serviceaccountuser to the same resource' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-65'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gi:GCP_IDENTITY { name: "allUsers"})
    OPTIONAL MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)<-[ir1:HAS_IAMROLE]-(gi)
    OPTIONAL MATCH (key:GCP_CLOUDKMS_CRYPTOKEY)<-[ir2:HAS_IAMROLE]-(gi)
    RETURN project.name as project_name, project.resource_data_name as display_name, key.name as key_name, ir1.role_name as project_role, ir2.role_name as key_role
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      if identity.project_name.nil? && identity.project_role.nil? && identity.key_name.nil? && identity.key_role.nil?
        describe 'No affected resources found', control_pack: control_pack, control_id: control_id,
                                                "#{control_id}": true do
          it 'should not have allUsers access to projects or cryptokeys' do
            expect(true).to eq(true)
          end
        end
      else
        resource_name = "#{identity.project_name}[#{identity.display_name}]" || identity.key_name
        describe resource_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
          it 'should not have allUsers access to projects or cryptokeys' do
            expect(resource_name).to be_nil
          end
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have allUsers access to projects or cryptokeys' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-66'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (key:GCP_CLOUDKMS_CRYPTOKEY)
    WHERE key.resource_data_primary_state = "ENABLED"
      AND key.resource_data_purpose = "ENCRYPT_DECRYPT"
    RETURN key.name as name , key.resource_data_primary_generateTime as last_generated
  )
  keys = graphdb.query(q).mapped_results
  if keys.length > 0
    keys.each do |key|
      describe key.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be older than 90 days' do
          days_old = (DateTime.now - DateTime.parse(key.last_generated)).to_i
          expect(days_old).to be <= 90
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be older than 90 days' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-67'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gi:GCP_IDENTITY)-[ir1:HAS_IAMROLE]->(resource)
    MATCH (gi)-[ir2:HAS_IAMROLE]->(resource)
    WHERE ir1.role_name = "roles/cloudkms.admin"
      AND ir2.role_name = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    RETURN DISTINCT gi.name as identity_name, resource.name as resource_name
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      describe "#{identity.identity_name}: [#{identity.resource_name}]", control_pack: control_pack,
                                                                         control_id: control_id, "#{control_id}": true do
        it 'should not have kms admin and cryptokeyencrypeterdecrypter to the same resource' do
          expect(identity.resource_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have kms admin and cryptokeyencrypeterdecrypter to the same resource' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Traverse PROJECT or FOLDER for any GCP_LOGGING_LOGSINK
control_id = 'rule-gcp-72'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (l:GCP_LOGGING_LOGSINK)-[:IN_HIERARCHY]->(p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    RETURN p.name as project_name, p.resource_data_name as display_name, l.name as sink_name, l.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a full logsink' do
          expect(project.sink_name).not_to be_nil
          expect(project.sink_filter).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a full logsink' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Log sink -> Storage Bucket
control_id = 'rule-gcp-73'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (ls:GCP_LOGGING_LOGSINK)-[:LOGS_TO]->(b:GCP_STORAGE_BUCKET)
    RETURN b.name as name, b.resource_data_retentionPolicy_retentionPeriod as log_retention, b.resource_data_retentionPolicy_isLocked as bucket_lock
  )
  buckets = graphdb.query(q).mapped_results
  if buckets.length > 0
    buckets.each do |bucket|
      describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have retention policies and bucket lock enabled' do
          expect(bucket.log_retention).to be > 0
          expect(bucket.bucket_lock).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have retention policies and bucket lock enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-74'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\""
       AND sink.resource_data_filter CONTAINS "ProjectOwnership"
       AND sink.resource_data_filter CONTAINS "projectOwnerInvitee"
       AND sink.resource_data_filter CONTAINS "protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\""
       AND sink.resource_data_filter CONTAINS "protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\""
       AND sink.resource_data_filter CONTAINS "protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\""
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for ownership changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for ownership changes' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-75'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "protoPayload.methodName=\"SetIamPolicy\""
       AND sink.resource_data_filter CONTAINS "protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for audit changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for audit changes' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-76'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "resource.type=\"gce_firewall_rule\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.firewalls.patch\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.firewalls.insert\""
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for firewall rule changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for firewall rule changes' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-77'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "resource.type=\"gce_route\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.routes.delete\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.routes.insert\""
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for route changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for route changes' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-78'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "resource.type=\"gce_network\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.networks.insert\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.networks.patch\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.networks.delete\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.networks.removePeering\""
       AND sink.resource_data_filter CONTAINS "jsonPayload.event_subtype=\"compute.networks.addPeering\""
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for network changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for network changes' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-79'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "resource.type=\"gcs_bucket\""
       AND sink.resource_data_filter CONTAINS "protoPayload.methodName=\"storage.setIamPermissions\""
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for storage IAM changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for storage IAM changes' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-80'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "protoPayload.methodName=\"cloudsql.instances.update\"")
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for cloudsql instance changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for cloudsql instance changes' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-81'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (v:GCP_COMPUTE_NETWORK)
    WHERE v.resource_data_name IS NOT NULL
    RETURN v.name as vpc_name, v.resource_data_IPv4Range as legacy_range
  )
  vpcs = graphdb.query(q).mapped_results
  if vpcs.length > 0
    vpcs.each do |vpc|
      describe vpc.vpc_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be a legacy VPC' do
          expect(vpc.legacy_range).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be a legacy VPC' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-82'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (zone:GCP_DNS_MANAGEDZONE)
    RETURN zone.name as name, zone.resource_data_dnssecConfig_state as state
  )
  zones = graphdb.query(q).mapped_results
  if zones.length > 0
    zones.each do |zone|
      describe zone.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have DNSSEC enabled' do
          expect(zone.state).to eq('ON')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have DNSSEC enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-83'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (zone:GCP_DNS_MANAGEDZONE)
    RETURN zone.name as name, zone.resource_data_dnssecConfig_state as state, zone.resource_data_dnssecConfig_defaultKeySpecs_0_keyType as first_type, zone.resource_data_dnssecConfig_defaultKeySpecs_0_algorithm as first_algorithm, zone.resource_data_dnssecConfig_defaultKeySpecs_1_keyType as second_type, zone.resource_data_dnssecConfig_defaultKeySpecs_1_algorithm as second_algorithm
  )
  zones = graphdb.query(q).mapped_results
  if zones.length > 0
    zones.each do |zone|
      zone_type = nil
      zone_algorithm = nil

      if zone.first_type == 'KEY_SIGNING'
        zone_type = zone.first_type
        zone_algorithm = zone.first_algorithm
      end
      if zone.second_type == 'KEY_SIGNING'
        zone_type = zone.second_type
        zone_algorithm = zone.second_algorithm
      end

      describe zone.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have RSASHA1 for the Key Signing Key' do
          expect(zone_algorithm).not_to eq('RSASHA1')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have RSASHA1 for the Signing Key' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-84'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (zone:GCP_DNS_MANAGEDZONE)
    RETURN zone.name as name, zone.resource_data_dnssecConfig_state as state, zone.resource_data_dnssecConfig_defaultKeySpecs_0_keyType as first_type, zone.resource_data_dnssecConfig_defaultKeySpecs_0_algorithm as first_algorithm, zone.resource_data_dnssecConfig_defaultKeySpecs_1_keyType as second_type, zone.resource_data_dnssecConfig_defaultKeySpecs_1_algorithm as second_algorithm
  )
  zones = graphdb.query(q).mapped_results
  if zones.length > 0
    zones.each do |zone|
      zone_type = nil
      zone_algorithm = nil

      if zone.first_type == 'ZONE_SIGNING'
        zone_type = zone.first_type
        zone_algorithm = zone.first_algorithm
      end
      if zone.second_type == 'ZONE_SIGNING'
        zone_type = zone.second_type
        zone_algorithm = zone.second_algorithm
      end

      describe zone.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have RSASHA1 for the Zone Signing Key' do
          expect(zone_algorithm).not_to eq('RSASHA1')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have RSASHA1 for the Signing Key' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-85'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_COMPUTE_INSTANCE)-[r:HAS_SERVICEACCOUNT]->(gi:GCP_IDENTITY)
    WHERE c.resource_data_labels_goog_gke_node IS NULL
    RETURN c.name as name, gi.resource_data_email as sa_name
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have the default ServiceAccount attached' do
          expect(instance.sa_name).not_to include('-compute@developer.gserviceaccount.com')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have the default ServiceAccount attached' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-86'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    OPTIONAL MATCH (i)-[r:HAS_OAUTHSCOPE]->(s:GCP_IAM_OAUTHSCOPE { name: 'https://www.googleapis.com/auth/cloud-platform'} )
    RETURN i.name as name, s.name as cloud_platform_scope
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have cloud-platform oauth scope assigned' do
          expect(instance.cloud_platform_scope).to eq(nil)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have cloud-platform oauth scope assigned' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-87'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gce:GCP_COMPUTE_INSTANCE)
    OPTIONAL MATCH (gce)-[itemvalue:HAS_METADATAITEM]->(item:GCP_COMPUTEMETADATAITEM)
    WHERE item.name = 'block-project-ssh-keys'
    RETURN gce.name as instance_name, itemvalue.value as setting
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should block project ssh keys' do
          expect(instance.setting).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should block project ssh keys' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-88'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gce:GCP_COMPUTE_INSTANCE)
    OPTIONAL MATCH (gce)-[itemvalue:HAS_METADATAITEM]->(item:GCP_COMPUTEMETADATAITEM)
    WHERE item.name = 'enable-oslogin' and gce.resource_data_labels_goog_gke_node IS NULL
    RETURN gce.name as instance_name, itemvalue.value as setting
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should enable oslogin' do
          expect(instance.setting).to eq('TRUE').or be_truthy
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should enable oslogin' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-89'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gce:GCP_COMPUTE_INSTANCE)
    OPTIONAL MATCH (gce)-[itemvalue:HAS_METADATAITEM]->(item:GCP_COMPUTEMETADATAITEM)
    WHERE item.name = 'serial-port-enable'
    RETURN gce.name as instance_name, itemvalue.value as setting
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should block serial port access' do
          expect(instance.setting).to eq('0')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should block serial port access' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-90'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    RETURN i.name as name, i.resource_data_canIpForward as can_ip_forward
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have ip forwarding enabled' do
          expect(instance.can_ip_forward).to eq('false')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have ip forwarding enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-91'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_COMPUTE_INSTANCE)-[:HAS_DISK]->(disk:GCP_COMPUTE_DISK)
    WHERE instance.resource_data_labels_goog_gke_node IS NULL
    RETURN instance.name as instance_name, disk.resource_data_diskEncryptionKey_kmsKeyName as key_name
  )
  gcenodes = graphdb.query(q).mapped_results
  if gcenodes.length > 0
    gcenodes.each do |node|
      describe node.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have CMEK configured for its disks' do
          expect(node.key_name).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have CMEK configured for its disks' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-92'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH  (i:GCP_COMPUTE_INSTANCE)
    WHERE  i.resource_data_labels_goog_gke_node IS NULL
    RETURN i.name as instance_name,
           i.resource_data_shieldedInstanceConfig_enableIntegrityMonitoring as integrity_monitoring,
           i.resource_data_shieldedInstanceConfig_enableSecureBoot as secure_boot,
           i.resource_data_shieldedInstanceConfig_enableVtpm as enable_vtpm
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have shielded node configuration enabled' do
          expect(instance.integrity_monitoring).to eq('true')
          expect(instance.secure_boot).to eq('true')
          expect(instance.enable_vtpm).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have shielded node configuration enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-94'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gi:GCP_IDENTITY { name: "allUsers" })
    OPTIONAL MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)<-[ir1:HAS_IAMROLE]-(gi)
    OPTIONAL MATCH (bucket:GCP_STORAGE_BUCKET)<-[ir2:HAS_IAMROLE]-(gi)
    RETURN project.name as project_name, project.resource_data_name as display_name, bucket.name as bucket_name, ir1.role_name as project_role, ir2.role_name as bucket_role
    UNION
    MATCH (gi:GCP_IDENTITY { name: "allAuthenticatedUsers" })
    OPTIONAL MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)<-[ir1:HAS_IAMROLE]-(gi)
    OPTIONAL MATCH (bucket:GCP_STORAGE_BUCKET)<-[ir2:HAS_IAMROLE]-(gi)
    RETURN project.name as project_name, project.resource_data_name as display_name, bucket.name as bucket_name, ir1.role_name as project_role, ir2.role_name as bucket_role
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      if identity.project_name.nil? && identity.project_role.nil? && identity.bucket_name.nil? && identity.bucket_role.nil?
        describe 'No affected resources found', control_pack: control_pack, control_id: control_id,
                                                "#{control_id}": true do
          it 'should not have all(Authenticated)Users access to projects or buckets' do
            expect(true).to eq(true)
          end
        end
      else
        resource_name = "#{identity.bucket_name}: #{identity.bucket_role}" || identity.key_name
        describe resource_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
          it 'should not have all(Authenticated)Users access to projects or buckets' do
            expect(resource_name).to be_nil
          end
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have all(Authenticated)Users access to projects or buckets' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-95'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name as name, b.resource_data_iamConfiguration_uniformBucketLevelAccess_enabled as uniform_iam_access
  )
  buckets = graphdb.query(q).mapped_results
  if buckets.length > 0
    buckets.each do |bucket|
      describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have uniform IAM access configured' do
          expect(bucket.uniform_iam_access).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have uniform IAM access configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-97'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'MYSQL'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'local_infile'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have local_infile disabled' do
          expect(instance.setting_value).to eq('off')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have local_infile disabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-98'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_checkpoints'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_checkpoints enabled' do
          expect(instance.setting_value).to eq('on')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_checkpoints enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-99'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_connections'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_connections enabled' do
          expect(instance.setting_value).to eq('on')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_connections enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-100'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_disconnections'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_disconnections enabled' do
          expect(instance.setting_value).to eq('on')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_disconnections enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-101'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_lock_waits'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_lock_waits enabled' do
          expect(instance.setting_value).to eq('on')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_lock_waits enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-102'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_min_error_statement'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_min_error_statement set to ERROR' do
          expect(instance.setting_value).to eq('ERROR')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_min_error_statement set to ERROR' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-103'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_temp_files'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_temp_files enabled' do
          expect(instance.setting_value).to eq('-1')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_temp_files enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-104'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'POST'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'log_min_duration_statement'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have log_min_duration_statement disabled' do
          expect(instance.setting_value).to eq('-1')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log_min_duration_statement disabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-105'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'SQLSERVER'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'cross db ownership chaining'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have cross db ownership chaining disabled' do
          expect(instance.setting_value).to eq('off')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have cross db ownership chaining disabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-106'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    WHERE sql.resource_data_databaseVersion STARTS WITH 'SQLSERVER'
    OPTIONAL MATCH (sql)-[flagvalue:HAS_SQLADMIN_DBFLAG]->(flag:GCP_SQLADMIN_DBFLAG)
    WHERE flag.name = 'contained database authentication'
    RETURN sql.name as instance_name, flagvalue.setting_value as setting_value
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have contained database authentication disabled' do
          expect(instance.setting_value).to eq('off')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have contained database authentication disabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-107'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    OPTIONAL MATCH (sql)-[:HAS_SQLMASTERAUTHORIZEDNETWORK]->(an:GCP_SQLADMIN_MASTERAUTHORIZEDNETWORK)
    WHERE NOT an.cidr_block = '0.0.0.0/0'
    RETURN sql.name as instance_name, count(an) as authorized_networks
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have not allow connections from all IPs' do
          expect(instance.authorized_networks.to_i).to be > 0
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have not allow connections from all IPs' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-108'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (gi:GCP_IDENTITY { name: "allUsers" })
    OPTIONAL MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)<-[ir1:HAS_IAMROLE]-(gi)
    OPTIONAL MATCH (dataset:GCP_BIGQUERY_DATASET)<-[ir2:HAS_IAMROLE]-(gi)
    RETURN project.name as project_name, project.resource_data_name as display_name, dataset.name as dataset_name, ir1.role_name as project_role, ir2.role_name as dataset_role
    UNION
    MATCH (gi:GCP_IDENTITY { name: "allAuthenticatedUsers" })
    OPTIONAL MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)<-[ir1:HAS_IAMROLE]-(gi)
    OPTIONAL MATCH (dataset:GCP_BIGQUERY_DATASET)<-[ir2:HAS_IAMROLE]-(gi)
    RETURN project.name as project_name, project.resource_data_name as display_name, dataset.name as dataset_name, ir1.role_name as project_role, ir2.role_name as dataset_role
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      if identity.project_name.nil? && identity.project_role.nil? && identity.dataset_name.nil? && identity.dataset_role.nil?
        describe 'No affected resources found', control_pack: control_pack, control_id: control_id,
                                                "#{control_id}": true do
          it 'should not have all(Authenticated)Users access to projects or datasets' do
            expect(true).to eq(true)
          end
        end
      else
        resource_name = "#{identity.project_name}[#{identity.display_name}]" || identity.key_name
        describe resource_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
          it 'should not have all(Authenticated)Users access to projects or datasets' do
            expect(resource_name).to be_nil
          end
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have all(Authenticated)Users access to projects or datasets' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-109'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_masterAuth_clientCertificate as client_cert_auth
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have client certificate authentication enabled' do
          expect(cluster.client_cert_auth).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have client certificate authentication enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-110'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)-[:HAS_RESOURCE]->(storagesvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "containerregistry.googleapis.com"})
    MATCH (project)-[:HAS_RESOURCE]->(bucket:GCP_STORAGE_BUCKET)
    WHERE bucket.resource_data_name STARTS WITH 'artifacts.' and bucket.resource_data_name ENDS WITH '.appspot.com'
    OPTIONAL MATCH (project)-[:HAS_RESOURCE]->(conscansvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "containerscanning.googleapis.com"})
    RETURN project.name as project_name, project.resource_data_name as display_name, conscansvc.name as svc_name
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have container vulnerability scanning enabled' do
          expect(project.svc_name).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have container vulnerability scanning enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-111'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (bucket:GCP_STORAGE_BUCKET)<-[:HAS_RESOURCE]-(project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    MATCH (project)-[:HAS_RESOURCE]->(storagesvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "containerregistry.googleapis.com"})
    WITH project, bucket
    WHERE bucket.resource_data_name STARTS WITH 'artifacts.' and bucket.resource_data_name ENDS WITH '.appspot.com'
    OPTIONAL MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)<-[ir:HAS_IAMROLE]-(gi:GCP_IDENTITY)
    WHERE
    (
       ir.role_name = 'roles/storage.admin'
    OR ir.role_name = 'roles/storage.objectAdmin'
    OR ir.role_name = 'roles/storage.objectCreator'
    OR ir.role_name = 'roles/storage.legacyBucketOwner'
    OR ir.role_name = 'roles/storage.legacyBucketWriter'
    OR ir.role_name = 'roles/storage.legacyObjectOwner'
    )
    RETURN gi.name as identity_name, ir.role_name as role_name, bucket.name as bucket_name
    UNION
    MATCH (bucket:GCP_STORAGE_BUCKET)<-[:HAS_RESOURCE]-(project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    MATCH (project)-[:HAS_RESOURCE]->(storagesvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "containerregistry.googleapis.com"})
    WITH project, bucket
    WHERE bucket.resource_data_name STARTS WITH 'artifacts.' and bucket.resource_data_name ENDS WITH '.appspot.com'
    OPTIONAL MATCH (bucket:GCP_STORAGE_BUCKET)<-[ir:HAS_IAMROLE]-(gi:GCP_IDENTITY)
    WHERE
    (
       ir.role_name = 'roles/storage.admin'
    OR ir.role_name = 'roles/storage.objectAdmin'
    OR ir.role_name = 'roles/storage.objectCreator'
    OR ir.role_name = 'roles/storage.legacyBucketOwner'
    OR ir.role_name = 'roles/storage.legacyBucketWriter'
    OR ir.role_name = 'roles/storage.legacyObjectOwner'
    )
    RETURN gi.name as identity_name, ir.role_name as role_name, bucket.name as bucket_name
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      resource_name = "#{identity.identity_name} has #{identity.role_name} on #{identity.bucket_name}"
      describe resource_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should be reviewed to see if access is needed' do
          expect(resource_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should be reviewed to see if access is needed' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-112'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (bucket:GCP_STORAGE_BUCKET)<-[:HAS_RESOURCE]-(project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    MATCH (project)-[:HAS_RESOURCE]->(storagesvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "containerregistry.googleapis.com"})
    WITH project, bucket
    WHERE bucket.resource_data_name STARTS WITH 'artifacts.' and bucket.resource_data_name ENDS WITH '.appspot.com'
    MATCH (nodepool:GCP_CONTAINER_NODEPOOL)-[:HAS_SERVICEACCOUNT]->(gi:GCP_IDENTITY)-[av:HAS_ACCESSVIA]->(role:GCP_IAM_ROLE)
    WITH project, bucket, nodepool, gi, av, role
    OPTIONAL MATCH (nodepool)-[:HAS_OAUTHSCOPE]->(scope:GCP_IAM_OAUTHSCOPE)
    WHERE (scope.name = 'https://www.googleapis.com/auth/devstorage.read_only')
    OPTIONAL MATCH (role)-[:HAS_PERMISSION]->(perm:GCP_IAM_PERMISSION { name: "storage.objects.create"})
    WHERE (av.resource = project.name OR av.resource = bucket.name)
    RETURN DISTINCT nodepool.name as nodepool_name, scope.name as scope_name, perm.name as perm_name
  )
  nodepools = graphdb.query(q).mapped_results
  if nodepools.length > 0
    pools = nodepools.group_by { |r| r[:nodepool_name] }.map do |np, perms|
      writable = (perms.select do |k, _v|
                    (k['scope_name'].nil? && k['perm_name'] == 'storage.objects.create')
                  end.length > 0) || false
      [np, writable]
    end
    pools.each do |nodepool|
      describe nodepool[0], control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have read-only access to GCR' do
          expect(nodepool[1]).to eq(false)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have read-only access to GCR' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-113'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.config_metadata_disable_legacy_endpoints as disabled_legacy_metadata
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have legacy metadata endpoints disabled' do
          expect(nodepool.disabled_legacy_metadata).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have legacy metadata endpoints disabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-114'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_releaseChannel_channel as channel_type
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should use stable or regular channel' do
          expect(cluster.channel_type).not_to eq('RAPID')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should use stable or regular channel' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-115'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_privateClusterConfig_enablePrivateNodes as private_nodes
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have private nodes configured' do
          expect(cluster.private_nodes).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have private nodes configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-116'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (cluster:GCP_CONTAINER_CLUSTER)-[:IN_SUBNETWORK]->(subnet:GCP_COMPUTE_SUBNETWORK)<-[:HAS_SUBNETWORK]-(vpc:GCP_COMPUTE_NETWORK)
    WITH cluster, subnet, vpc

    OPTIONAL MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(fwi:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL), (fwi)<-[:HAS_FIREWALL]-(vpc)
    WHERE ((rule.from_port <= 22 AND 22 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    WITH fwi, cluster, subnet, vpc

    OPTIONAL MATCH (fwe:GCP_COMPUTE_FIREWALL {resource_data_direction: "EGRESS"})-[rule:HAS_FIREWALLRULE { action: "deny"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL { name: 'all'}), (fwe)<-[:HAS_FIREWALL]-(vpc)
    WITH cluster, subnet, vpc, fwi, fwe

    RETURN cluster.name as cluster_name, cluster.resource_data_privateClusterConfig_enablePrivateNodes as private_nodes, count(fwi) as ssh_ingress, count(fwe) as deny_egress
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.cluster_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have private nodes configured, no SSH inbound, and a default deny egress fw rule' do
          expect(cluster.private_nodes).to eq('true')
          expect(cluster.ssh_ingress.to_i).to eq(0)
          expect(cluster.deny_egress.to_i).to be > 0
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have private nodes configured, no SSH inbound, and a default deny egress fw rule' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-117'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (ing:K8S_INGRESS)
    WHERE NOT ing.resource_data_metadata_annotations_ingress_dot_kubernetes_dot_io_slash_https_target_proxy IS NULL
    RETURN ing.name as name, ing.resource_data_metadata_annotations_networking_dot_gke_dot_io_slash_managed_certificates as cert
  )
  ingresses = graphdb.query(q).mapped_results
  if ingresses.length > 0
    ingresses.each do |ingress|
      describe ingress.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have google-managed cert attached' do
          expect(ingress.cert).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have google-managed cert attached' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-121'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_authenticatorGroupsConfig_enabled as google_groups_rbac
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have google groups RBAC integration configured' do
          expect(cluster.google_groups_rbac).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have google groups RBAC integration configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-122'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_COMPUTE_INSTANCE)-[:HAS_DISK]->(disk:GCP_COMPUTE_DISK)
    WHERE NOT instance.resource_data_labels_goog_gke_node IS NULL
    RETURN instance.name as instance_name, disk.resource_data_diskEncryptionKey_kmsKeyName as key_name
  )
  gkenodes = graphdb.query(q).mapped_results
  if gkenodes.length > 0
    gkenodes.each do |node|
      describe node.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have CMEK configured for its disks' do
          expect(node.key_name).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have CMEK configured for its disks' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-123'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_enableKubernetesAlpha as alpha
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not run alpha clusters' do
          expect(cluster.alpha).not_to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not run alpha clusters' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-124'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (np:GCP_CONTAINER_NODEPOOL)
    WHERE NOT np.name ENDS WITH '/default-pool'
    RETURN np.name as nodepool_name, np.resource_data_config_sandboxConfig_sandboxType as sandbox_type
  )
  nps = graphdb.query(q).mapped_results
  if nps.length > 0
    nps.each do |np|
      describe np.nodepool_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have gVisor enabled' do
          expect(np.sandbox_type).to eq('GVISOR')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have gVisor enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-125'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_binaryAuthorization_enabled as binary_authorization
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have binary authorization enabled' do
          expect(cluster.binary_authorization).to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have binary authorization enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-127'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_masterAuth_username as basic_auth_user
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have basic authentication enabled' do
          expect(cluster.basic_auth_user).not_to eq('admin')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have basic authentication enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

# FUTURE: Parse up folder chain and check for alert metrics
control_id = 'rule-gcp-128'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    OPTIONAL MATCH (sink:GCP_LOGGING_LOGSINK)<-[:HAS_RESOURCE]-(project)
    WHERE (sink.resource_data_filter CONTAINS "resource.type=\"iam_role\""
       AND sink.resource_data_filter CONTAINS "google.iam.admin.v1.CreateRole"
       AND sink.resource_data_filter CONTAINS "google.iam.admin.v1.DeleteRole"
       AND sink.resource_data_filter CONTAINS "google.iam.admin.v1.UpdateRole"
    )
    RETURN project.name as project_name, project.resource_data_name as display_name, sink.resource_data_filter as sink_filter
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have a logsink filter for custom role changes' do
          expect(project.sink_filter).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a logsink filter for custom role changes' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-129'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name AS name, b.resource_data_iamConfiguration_bucketPolicyOnly_enabled AS is_bucket
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have uniform bucket-level access enabled' do
        expect(bucket.is_bucket).to eq('true')
      end
    end
  end
end

control_id = 'rule-gcp-131'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_IDENTITY { member_type: 'serviceAccount' })-[r:HAS_IAMROLE]-(p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    WHERE c.name ENDS WITH '-compute@developer.gserviceaccount.com'
    RETURN c.name as name, r.role_name as role_name
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    records = sas.group_by { |r| r[:name] }.map do |id, roles|
      editor = (roles.select { |k, _v| (k['role_name'] == 'roles/editor') }.length > 0) || false
      [id, editor]
    end
    records.each do |sa|
      describe sa[0], control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have Editor bound to the default service account' do
          expect(sa[1]).to eq(false)
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have Editor bound to the default service account' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-132'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    OPTIONAL MATCH (i)-[:HAS_NETWORKACCESSCONFIG]->(n:GCP_COMPUTE_NETWORKACCESSCONFIG)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    return i.name as name, n.type as network_type
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have a private IP' do
          expect(instance.network_type).not_to eq('ONE_TO_ONE_NAT')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a private IP' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-133'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sa:GCP_IAM_SERVICEACCOUNTKEY)
    WHERE sa.resource_data_keyType = "USER_MANAGED"
      and NOT sa.resource_data_validAfterTime IS NULL
    RETURN sa.name as sa_name, sa.resource_data_validAfterTime as start_time
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      describe sa.sa_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be older than 90 days' do
          days_old = (DateTime.now - DateTime.parse(sa.start_time)).to_i
          expect(days_old).to be <= 90
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be older than 90 days' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-134'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
   MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
   OPTIONAL MATCH (project)-[r:HAS_AUDITCONFIG]->(svc:GCP_CLOUDRESOURCEMANAGER_PROJECTAUDITSERVICE)
   WHERE svc.name = 'allServices'
   RETURN project.name as project_name, project.resource_data_name as display_name, r.log_type as log_type, r.exempted_members as exempted_members
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    configs = projects.group_by { |r| "#{r[:project_name]}[#{r[:display_name]}]" }.map do |np, configs|
      log_types = configs.group_by { |s| s[:log_type] }.map { |k, _v| k }.sort
      exempted_members = configs.group_by { |s| s[:exempted_members] }.map { |k, _v| k }.compact
      [np, log_types, exempted_members]
    end
    configs.each do |config|
      describe config[0], control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have audit logging configured' do
          expect(config[1]).to eq(%w[1 2 3])
          expect(config[2]).to eq([])
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have audit logging configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-135'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sak:GCP_IAM_SERVICEACCOUNTKEY)
    WHERE sak.resource_data_keyType = "USER_MANAGED"
    RETURN DISTINCT sak.resource_parent as sa_id
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      sa_id = sa.sa_id.gsub(%r{^//}, '')
      describe sa_id, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have user-managed keys' do
          expect(sa_id).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have user-managed keys' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-136'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(f:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS", resource_data_disabled: "false" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL)
    WHERE ((rule.from_port <= 80 AND 80 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    RETURN DISTINCT f.name as firewall_name
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not allow TCP/80 from 0.0.0.0/0' do
          expect(fw.firewall_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not allow TCP/80 from 0.0.0.0/0' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-137'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(f:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS", resource_data_disabled: "false" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL)
    WHERE ((rule.from_port <= 23 AND 23 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    RETURN DISTINCT f.name as firewall_name
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not allow TCP/23 from 0.0.0.0/0' do
          expect(fw.firewall_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not allow TCP/23 from 0.0.0.0/0' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-138'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(f:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS", resource_data_disabled: "false" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL)
    WHERE ((rule.from_port <= 110 AND 110 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    RETURN DISTINCT f.name as firewall_name
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not allow TCP/110 from 0.0.0.0/0' do
          expect(fw.firewall_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not allow TCP/110 from 0.0.0.0/0' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-139'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (range:GCP_COMPUTE_FIREWALLIPRANGE { name: "0.0.0.0/0"})<-[:HAS_SOURCEIPRANGE]-(f:GCP_COMPUTE_FIREWALL { resource_data_direction: "INGRESS", resource_data_disabled: "false" })-[rule:HAS_FIREWALLRULE { action: "allow"}]->(proto:GCP_COMPUTE_NETWORKPROTOCOL)
    WHERE ((rule.from_port <= 3306 AND 3306 <= rule.to_port) AND (proto.name = 'all' OR proto.name = 'tcp'))
    RETURN DISTINCT f.name as firewall_name
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not allow TCP/3306 from 0.0.0.0/0' do
          expect(fw.firewall_name).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not allow TCP/3306 from 0.0.0.0/0' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-140'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (h:GCP_HEALTHCARE_DATASET)<-[:HAS_RESOURCE]-(project:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    RETURN project.name as project_name, project.resource_data_name as display_name, h.name as name
  )
  datasets = graphdb.query(q).mapped_results
  if datasets.length > 0
    datasets.each do |dataset|
    pp dataset
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have an dataset configured in system' do
          expect(dataset.name)._to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have an dataset.name configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-141'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (s:GCP_COMPUTE_SUBNETWORK)
    RETURN s.name as name,
           s.resource_data_enableFlowLogs as flow_logs
  )
  subnets = graphdb.query(q).mapped_results
  if subnets.length > 0
    subnets.each do |subnet|
      describe subnet.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'VPC Flow Logs should be a enabled' do
          expect(subnet.flow_logs).not_to eq('false')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be a default VPC' do
        expect(true).to eq(true)
      end
    end
  end
end

#control_id = 'rule-gcp-142'
#RSpec.describe "[#{control_id}] #{titles[control_id]}" do
#  q = %s(
#    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)-[:HAS_RESOURCE]->(table:GCP_BIGQUERY_TABLE)
#    RETURN project.name as project_name, project.resource_data_name as display_name, table.name as table_name, table.resource_data_encryptionConfiguration_kmsKeyName as kms_key
#  )
#  kmskeys = graphdb.query(q).mapped_results
#  if kmskeys.length > 0
#    kmskeys.each do |kmskey|
#      describe kmskey.table_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
#        it 'should not have KMS key access to projects or datasets' do
#          expect(kmskey.kms_key).not_to be_nil
#        end
#      end
#    end
#  else
#    describe kmskey.table_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
#      it 'should have kms keys access to projects or datasets' do
#        expect(true).to eq(true)
#      end
#    end
#  end
#end

control_id = 'rule-gcp-143'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)-[:HAS_RESOURCE]->(storagesvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "healthcare.googleapis.com"})
    OPTIONAL MATCH (project)-[:HAS_RESOURCE]->(conscansvc:GCP_SERVICEUSAGE_SERVICE { resource_data_name: "healthcare.googleapis.com"})
    RETURN project.name as project_name, project.resource_data_name as display_name, conscansvc.name as svc_name
  )
  projects = graphdb.query(q).mapped_results
  if projects.length > 0
    projects.each do |project|
      describe "#{project.project_name}[#{project.display_name}]", control_pack: control_pack, control_id: control_id,
                                                                   "#{control_id}": true do
        it 'should have container vulnerability scanning enabled' do
          expect(project.svc_name).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have container vulnerability scanning enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-145'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (v:GCP_COMPUTE_NETWORK)
    WHERE NOT v.resource_data_name IS NULL
    RETURN v.name as vpc_name, v.resource_data_autoCreateSubnetworks as custom_mode
  )
  vpcs = graphdb.query(q).mapped_results
  if vpcs.length > 0
    vpcs.each do |vpc|
      describe vpc.vpc_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be a custom mode in VPC' do
          expect(vpc.custom_mode).not_to eq('true')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be a custom mode VPC enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-146'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (t:GCP_COMPUTE_NETWORKTAG)<-[:HAS_TARGETNETWORKTAG]-(f:GCP_COMPUTE_FIREWALL)
    RETURN f.name as firewall_name, t.name as tags
  )
  fws = graphdb.query(q).mapped_results
  if fws.length > 0
    fws.each do |fw|
      describe fw.firewall_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not use some tags' do
          expect(fw.tags).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should use some tags' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-147'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    RETURN sql.name as instance_name, sql.resource_data_ipConfiguration_ipv4Enabled as private_ip
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have public IPs' do
          expect(instance.private_ip).to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have public IPs' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-148'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    RETURN sql.name as instance_name, sql.resource_data_settings_userLabels as labels
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'SQL should use labels' do
          expect(instance.labels).not_to be_nil
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'SQL should use labels' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-149'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    RETURN sql.name as instance_name, sql.resource_data_settings_storageAutoResize as auto_size
  )
  instances = graphdb.query(q).mapped_results
  pp instances
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'SQL should use storage autoresize' do
          expect(instance.auto_size).not_to eq('false')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'SQL should use storage autoresize' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-150'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sql:GCP_SQLADMIN_INSTANCE)
    RETURN sql.name as instance_name, sql.resource_data_settings_backupConfiguration_enabled as backup
  )
  instances = graphdb.query(q).mapped_results
  pp instances
  if instances.length > 0
    instances.each do |instance|
      describe instance.instance_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'SQL should have enable backup' do
          expect(instance.backup).not_to eq('false')
        end
      end
    end
  else
    describe 'No affected resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'SQL should have enable backup' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'rule-gcp-151'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name AS name, b.resource_data_labels AS is_label
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have label provided' do
        expect(bucket.is_label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-152'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name AS name, b.resource_data_versioning_enabled AS is_versioning
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have versioning enabled' do
        expect(bucket.is_versioning).to eq('true')
      end
    end
  end
end

control_id = 'rule-gcp-153'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name AS name, b.resource_data_location AS location
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
  pp bucket
  buck_lock = [bucket.name, bucket.location].join('-')
    describe buck_lock, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should located in US' do
        expect(bucket.location).to eq('US')
      end
    end
  end
end

control_id = 'rule-gcp-154'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name AS name, b.resource_data_lifecycle AS is_lifecycle
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Buckets should have lifecycle enabled' do
        expect(bucket.is_lifecycle).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-155'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_STORAGE_BUCKET)
    RETURN b.name AS name, b.resource_data_logging AS log
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Backets should have logging enabled' do
        expect(bucket.log).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-156'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (pub:GCP_PUBSUB_TOPIC)
    RETURN pub.name AS name, pub.resource_data_labels AS labels
  )
  topics = graphdb.query(q).mapped_results
  topics.each do |topic|
    describe topic.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'PubSub should have labelb enabled' do
        expect(topic.labels).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-157'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (pub:GCP_PUBSUB_TOPIC)
    RETURN pub.name AS name, pub.resource_data_kmsKeyName AS key
  )
  topics = graphdb.query(q).mapped_results
  topics.each do |topic|
    describe topic.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'PubSub can have kmsKeyName enabled' do
        expect(topic.key).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-158'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sub:GCP_PUBSUB_SUBSCRIPTION)
    RETURN sub.name AS name, sub.resource_data_deadLetterPolicy AS policy
  )
  subscriptions = graphdb.query(q).mapped_results
  subscriptions.each do |subscription|
    describe subscription.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'PubSub can have _deadLetterPolicy enabled' do
        expect(subscription.policy).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-159'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sub:GCP_PUBSUB_SUBSCRIPTION)
    RETURN sub.name AS name, sub.resource_data_labels AS label
  )
  subscriptions = graphdb.query(q).mapped_results
  subscriptions.each do |subscription|
    describe subscription.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'PubSub have labels' do
        expect(subscription.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-160'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (pub:GCP_PUBSUB_SNAPSHOT)
    RETURN pub.name AS name, pub.resource_data_labels AS labels
  )
  snapshots = graphdb.query(q).mapped_results
  snapshots.each do |snapshot|
    describe snapshot.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'PubSub snapshot should have labelb enabled' do
        expect(snapshot.labels).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-161'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_BIGQUERY_DATASET)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  datasets = graphdb.query(q).mapped_results
  datasets.each do |dataset|
    describe dataset.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Bigquery dataset have labels' do
        expect(dataset.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-162'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_BIGQUERY_TABLE)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  tables = graphdb.query(q).mapped_results
  tables.each do |table|
    describe table.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Bigquery table have labels' do
        expect(table.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-163'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_BIGQUERY_MODEL)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  models = graphdb.query(q).mapped_results
  models.each do |model|
    describe model.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Bigquery model have labels' do
        expect(model.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-164'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_BIGTABLEADMIN_INSTANCE)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  bigtables = graphdb.query(q).mapped_results
  bigtables.each do |bigtable|
    describe bigtable.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Bigtable instances have labels' do
        expect(bigtable.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-165'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_DATAFLOW_JOB)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  dataflows = graphdb.query(q).mapped_results
  dataflows.each do |dataflow|
    describe dataflow.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'dataflow jobs have labels' do
        expect(dataflow.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-166'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_DATAPROC_JOB)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  dataprocs = graphdb.query(q).mapped_results
  dataprocs.each do |dataproc|
    describe dataproc.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'dataproc jobs have labels' do
        expect(dataproc.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-167'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_DATAPROC_CLUSTER)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  dataprocs = graphdb.query(q).mapped_results
  dataprocs.each do |dataproc|
    describe dataproc.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'dataproc clusters have labels' do
        expect(dataproc.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-168'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_CLOUDKMS_CRYPTOKEY)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  kms = graphdb.query(q).mapped_results
  kms.each do |key|
    describe key.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'KMS key has labels' do
        expect(key.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-169'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_CLOUDFUNCTIONS_CLOUDFUNCTION)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  functions = graphdb.query(q).mapped_results
  functions.each do |function|
    describe function.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'CloudFunction has labels' do
        expect(function.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-170'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_SPANNER_INSTANCE)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  dbs = graphdb.query(q).mapped_results
  dbs.each do |db|
    describe db.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Cloud Spanner has labels' do
        expect(db.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-171'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (b:GCP_COMPUTE_INSTANCE)
    RETURN b.name AS name, b.resource_data_labels AS label
  )
  instances = graphdb.query(q).mapped_results
  instances.each do |instance|
    describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'Compute Engine Instance has labels' do
        expect(instance.label).not_to be_nil
      end
    end
  end
end

control_id = 'rule-gcp-172'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_CONTAINER_CLUSTER)
    RETURN i.name AS name, i.resource_data_resourceLabels AS label
  )
  instances = graphdb.query(q).mapped_results
  instances.each do |instance|
    describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'GKE Instance has labels' do
        expect(instance.label).not_to be_nil
      end
    end
  end
end
