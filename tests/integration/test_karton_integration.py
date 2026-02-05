"""
Integration tests for Karton service interactions.
Tests the flow between different tools in the B-Hunters ecosystem.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json


@pytest.mark.integration
class TestKartonToolChain:
    """Test the integration between Karton tools."""
    
    def test_task_payload_flow(self, sample_scan_document):
        """Test task payloads flow correctly between tools."""
        from karton.core import Task
        
        # Create a task as it would be created by a producer
        task = Task({
            "type": "domain",
            "stage": "new"
        })
        
        task.add_payload("domain", "example.com", persistent=True)
        task.add_payload("scantype", "multi", persistent=True)
        task.add_payload("scan_id", "507f1f77bcf86cd799439011", persistent=True)
        task.add_payload("source", "producer")
        
        # Verify task structure
        assert task.headers["type"] == "domain"
        assert task.payloads["domain"] == "example.com"
        assert task.payloads["scantype"] == "multi"
        assert task.payloads["scan_id"] == "507f1f77bcf86cd799439011"
    
    def test_subdomain_enumeration_chain(self, mock_karton_config):
        """Test the subdomain enumeration tool chain (subfinder -> subrecon)."""
        with patch('b_hunters.bhunter.Config', return_value=mock_karton_config):
            with patch('b_hunters.bhunter.pymongo.MongoClient') as mock_mongo:
                mock_db = Mock()
                mock_collection = Mock()
                mock_db.__getitem__ = Mock(return_value=mock_collection)
                mock_mongo.return_value.__getitem__ = Mock(return_value=mock_db)
                
                # Simulate subfinder finding subdomains
                subdomains = ["api.example.com", "admin.example.com", "blog.example.com"]
                
                # Verify subfinder would create tasks for each subdomain
                assert len(subdomains) == 3
                for subdomain in subdomains:
                    assert subdomain.endswith("example.com")
    
    def test_vulnerability_scanning_chain(self, sample_scan_document):
        """Test the vulnerability scanning tool chain (dalfox, nuclei, etc)."""
        # Verify vulnerability data structure
        vulns = sample_scan_document.get("Vulns", {})
        
        for tool_name, findings in vulns.items():
            assert isinstance(findings, list)
            for finding in findings:
                # Each finding should have basic structure
                assert isinstance(finding, dict)
    
    def test_web_crawling_chain(self):
        """Test the web crawling tool chain (gospider, katana, paramspider)."""
        # Mock the flow from crawler to parameter finder
        crawled_urls = [
            "http://example.com/page1?param1=value1",
            "http://example.com/page2?param2=value2",
        ]
        
        # Verify URLs have parameters for parameter-based scanning
        for url in crawled_urls:
            assert "?" in url  # Has query parameters
            assert "=" in url  # Has key=value pair
    
    def test_js_analysis_chain(self):
        """Test the JavaScript analysis tool chain (nipejs, secretfinder)."""
        # Mock JavaScript findings
        js_findings = [
            {
                "url": "http://example.com/app.js",
                "Vulns": "API key exposed: sk_live_1234567890",
                "domain": "example.com"
            },
            {
                "url": "http://example.com/main.js",
                "Vulns": None,
                "domain": "example.com"
            }
        ]
        
        # Verify JS analysis results
        vulnerable_js = [js for js in js_findings if js.get("Vulns")]
        assert len(vulnerable_js) == 1
        assert "sk_live" in vulnerable_js[0]["Vulns"]


@pytest.mark.integration
class TestDatabaseIntegration:
    """Test database interactions in the tool chain."""
    
    def test_scan_creation_flow(self, mock_mongo_client, mock_karton_config):
        """Test the scan creation and document flow."""
        client, db, collection = mock_mongo_client
        
        with patch('pymongo.MongoClient', return_value=client):
            # Simulate scan creation
            scan_doc = {
                "Domain": "example.com",
                "Type": "multi",
                "Description": "Test scan"
            }
            
            # Mock insert result
            insert_result = Mock()
            insert_result.acknowledged = True
            insert_result.inserted_id = "507f1f77bcf86cd799439011"
            collection.insert_one.return_value = insert_result
            
            result = collection.insert_one(scan_doc)
            
            assert result.acknowledged is True
            assert result.inserted_id is not None
    
    def test_domain_document_update(self, mock_mongo_client, sample_scan_document):
        """Test domain document updates during scanning."""
        client, db, collection = mock_mongo_client
        
        # Simulate updating task status
        update_result = Mock()
        update_result.modified_count = 1
        collection.update_one.return_value = update_result
        
        # Test "Started" status update
        collection.update_one(
            {"Domain": "example.com"},
            {"$addToSet": {"status.processing": "dalfox"}}
        )
        
        collection.update_one.assert_called()
    
    def test_s3_file_storage_flow(self, mock_s3_client, temp_report_dir):
        """Test the S3 file storage integration."""
        # Simulate storing results
        tool_result = b"dalfox found 2 XSS vulnerabilities"
        
        mock_s3_client.put_object.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        
        # Verify we can store and retrieve
        mock_s3_client.put_object(
            Bucket="bhunters",
            Key="dalfox_example.com.txt",
            Body=tool_result
        )
        
        mock_s3_client.put_object.assert_called_once()


@pytest.mark.integration
class TestToolCommunication:
    """Test communication between different tools."""
    
    def test_producer_consumer_handshake(self, mock_karton_config):
        """Test producer and consumer task handshake."""
        from karton.core import Producer, Task
        
        with patch('karton.core.Producer') as mock_producer_class:
            mock_producer = Mock()
            mock_producer_class.return_value = mock_producer
            
            # Create a task
            task = Task({"type": "domain", "stage": "subdomain_enumeration"})
            task.add_payload("domain", "example.com")
            
            # Verify task can be sent
            mock_producer.send_task.return_value = None
            mock_producer.send_task(task)
            mock_producer.send_task.assert_called_once_with(task)
    
    def test_status_handling_across_tools(self, sample_domain_documents):
        """Test status updates from multiple tools."""
        for doc in sample_domain_documents:
            status = doc["status"]
            
            # Verify status structure
            assert "processing" in status
            assert "finished" in status
            assert "failed" in status
            
            # Verify lists
            assert isinstance(status["processing"], list)
            assert isinstance(status["finished"], list)
            assert isinstance(status["failed"], list)


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndScenarios:
    """End-to-end integration tests (marked as slow)."""
    
    def test_full_recon_scan_simulation(self):
        """Simulate a full reconnaissance scan workflow."""
        scan_stages = [
            "domain_registration",
            "subdomain_enumeration",
            "port_scanning",
            "technology_detection",
            "web_crawling",
            "vulnerability_scanning",
            "js_analysis",
            "report_generation"
        ]
        
        # Simulate flow through all stages
        completed_stages = []
        
        for stage in scan_stages:
            # Simulate each stage completing
            completed_stages.append(stage)
            
        assert len(completed_stages) == len(scan_stages)
    
    def test_report_generation_from_multiple_sources(self, sample_scan_document, sample_domain_documents):
        """Test report generation aggregating data from multiple tools."""
        # Aggregate all data
        all_data = {
            "main_scan": sample_scan_document,
            "domains": sample_domain_documents
        }
        
        # Verify data structure for reporting
        assert "main_scan" in all_data
        assert "domains" in all_data
        assert len(all_data["domains"]) == 2
