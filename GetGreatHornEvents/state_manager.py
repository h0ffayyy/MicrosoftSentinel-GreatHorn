from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
import logging
import datetime


class BlobStateManager:
    def __init__(self, connection_string, container_name='funcstate', blob_name='statemarker.txt'):
        self.connection_string = connection_string
        self.container_name = container_name
        self.blob_name = blob_name
        
        # Initialize clients
        self.blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        self.container_client = self.blob_service_client.get_container_client(container_name)
        self.blob_client = self.blob_service_client.get_blob_client(
            container=container_name, 
            blob=blob_name
        )
        
        # Ensure container exists
        self._ensure_container_exists()

    def _ensure_container_exists(self):
        """Create the container if it doesn't exist"""
        try:
            self.container_client.get_container_properties()
            logging.debug(f"Container '{self.container_name}' already exists")
        except ResourceNotFoundError:
            try:
                self.container_client.create_container()
                logging.info(f"Created container: {self.container_name}")
            except Exception as e:
                if "ContainerAlreadyExists" not in str(e):
                    logging.error(f"Failed to create container '{self.container_name}': {e}")
                    raise

    def post(self, marker_text: str):
        """Save state to blob storage"""
        try:
            self._ensure_container_exists()
            self.blob_client.upload_blob(marker_text, overwrite=True)
            logging.info(f"State saved to blob: {marker_text}")
        except Exception as e:
            logging.error(f"Failed to save state to blob: {e}")
            raise

    def get(self):
        """Get state from blob storage"""
        try:
            self._ensure_container_exists()
            content = self.blob_client.download_blob().readall().decode().strip()
            
            if not content:
                logging.warning("State blob is empty")
                return None
            
            # Validate timestamp format
            try:
                datetime.datetime.fromisoformat(content.replace('Z', '+00:00'))
                logging.debug(f"Retrieved valid state from blob: {content}")
                return content
            except ValueError as ve:
                logging.warning(f"Invalid timestamp format in state blob: {content} - {ve}")
                return None
                
        except ResourceNotFoundError:
            logging.info("No state blob found, this is normal for first run")
            return None
        except Exception as e:
            logging.error(f"Error retrieving state from blob: {e}")
            return None

    def delete_state(self):
        """Delete the state blob"""
        try:
            self.blob_client.delete_blob()
            logging.info("State blob deleted")
            return True
        except ResourceNotFoundError:
            logging.info("No state blob to delete")
            return True
        except Exception as e:
            logging.error(f"Failed to delete state blob: {e}")
            return False
