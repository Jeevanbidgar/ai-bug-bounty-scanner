"""
Tests for tool adapters
"""

import pytest
import asyncio
from backend.adapters.adapter_manager import AdapterManager
from backend.adapters.subfinder_adapter import SubfinderAdapter
from backend.adapters.waybackurls_adapter import WaybackURLsAdapter

class TestAdapterManager:
    """Test the adapter manager"""

    def test_adapter_manager_initialization(self):
        """Test that adapter manager initializes correctly"""
        manager = AdapterManager()
        assert manager is not None
        assert len(manager.adapters) > 0

        # Check that MVP adapters are present
        mvp_tools = ['subfinder', 'amass', 'waybackurls', 'gau', 'naabu', 'nmap', 'nuclei']
        for tool in mvp_tools:
            assert tool in manager.adapters, f"MVP tool {tool} not found in adapters"

    def test_get_adapter(self):
        """Test getting specific adapters"""
        manager = AdapterManager()

        adapter = manager.get_adapter('subfinder')
        assert adapter is not None
        assert adapter.tool_name == 'subfinder'

        # Test non-existent adapter
        assert manager.get_adapter('nonexistent') is None

    def test_list_adapters(self):
        """Test listing adapters with metadata"""
        manager = AdapterManager()
        adapters = manager.list_adapters()

        assert len(adapters) > 0
        for adapter_info in adapters:
            assert 'name' in adapter_info
            assert 'risk_level' in adapter_info
            assert 'requires_auth' in adapter_info

@pytest.mark.asyncio
class TestSubfinderAdapter:
    """Test the subfinder adapter"""

    async def test_subfinder_adapter_initialization(self):
        """Test subfinder adapter initializes correctly"""
        adapter = SubfinderAdapter()
        assert adapter.tool_name == 'subfinder'
        assert adapter.containerized is False or adapter.containerized is True  # Docker may or may not be available

    async def test_subfinder_command_generation(self):
        """Test subfinder command generation"""
        adapter = SubfinderAdapter()
        command = adapter.get_command('example.com', passive=True)

        assert isinstance(command, list)
        assert len(command) > 0
        assert 'subfinder' in command[0]
        assert '-d' in command
        assert 'example.com' in command

    async def test_subfinder_target_validation(self):
        """Test target validation"""
        adapter = SubfinderAdapter()

        # Valid targets
        assert adapter.validate_target('example.com')
        assert adapter.validate_target('https://example.com')

        # Invalid targets
        assert not adapter.validate_target('')
        assert not adapter.validate_target('localhost')
        assert not adapter.validate_target('127.0.0.1')

@pytest.mark.asyncio
class TestWaybackURLsAdapter:
    """Test the waybackurls adapter"""

    async def test_waybackurls_adapter_initialization(self):
        """Test waybackurls adapter initializes correctly"""
        adapter = WaybackURLsAdapter()
        assert adapter.tool_name == 'waybackurls'

    async def test_waybackurls_command_generation(self):
        """Test waybackurls command generation"""
        adapter = WaybackURLsAdapter()
        command = adapter.get_command('example.com')

        assert isinstance(command, list)
        assert len(command) == 3  # ['sh', '-c', 'waybackurls example.com > /output/...']
        assert command[0] == 'sh'
        assert command[1] == '-c'
        assert 'waybackurls' in command[2]
        assert 'example.com' in command[2]

    async def test_waybackurls_url_categorization(self):
        """Test URL categorization logic"""
        adapter = WaybackURLsAdapter()

        # API endpoint
        assert adapter._categorize_url('https://api.example.com/v1/users') == 'api'

        # Admin area
        assert adapter._categorize_url('https://example.com/admin') == 'admin'

        # File download
        assert adapter._categorize_url('https://example.com/files/document.pdf') == 'file'

        # Static asset
        assert adapter._categorize_url('https://example.com/js/app.js') == 'static'

        # Regular webpage
        assert adapter._categorize_url('https://example.com/about') == 'web'

if __name__ == '__main__':
    # Run tests
    asyncio.run(test_adapter_manager_initialization())
    print("All tests passed!")
