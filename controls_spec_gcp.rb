control_id = 'new-gcp-16'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (project:GCP_CLOUDRESOURCEMANAGER_PROJECT)-[:HAS_RESOURCE]->(dataset:GCP_BIGQUERY_DATASET)
    RETURN project.name as project_name, project.resource_data_name as display_name, dataset.name as dataset_name
  )
  kmskeys = graphdb.query(q).mapped_results
  pp kmskeys
  if kmskeys.length > 0
    kmskeys.each do |kmskey|
      describe kmskey.dataset_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have KMS key access to projects or datasets' do
          expect(kmskey.dataset_name).not_to be_nil
        end
      end
    end
  else
    describe kmskey.dataset_name, 'resources found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have kms keys access to projects or datasets' do
        expect(true).to eq(true)
      end
    end
  end
end
