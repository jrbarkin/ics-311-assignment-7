# Alana Wesly, ICS 311 08/08/2025 Assigment 7
import numpy as np

class LossyCompression:
    @staticmethod
    def compress_message(message: str, keep_ratio: float):
        """
        Compress message using FFT and discard high-frequency components.
        keep_ratio: fraction of coefficients to keep (0 < keep_ratio <= 1)
        """
        if not (0 < keep_ratio <= 1):
            raise ValueError("keep_ratio must be between 0 and 1")
        
        # Convert string to numerical array
        message_bytes = np.frombuffer(message.encode('utf-8'), dtype=np.uint8).astype(float)
        original_length = len(message_bytes)

        # FFT transform
        freq_domain = np.fft.fft(message_bytes)

        # Determine number of coefficients to keep
        k = int(len(freq_domain) * keep_ratio)
        indices = np.argsort(np.abs(freq_domain))  # sort by magnitude

        # Zero out smallest coefficients
        freq_domain[indices[:-k]] = 0

        # Inverse FFT to reconstruct compressed signal
        compressed_signal = np.fft.ifft(freq_domain).real
        compressed_signal = np.round(np.clip(compressed_signal, 0, 255)).astype(np.uint8)

        # Convert back to string
        compressed_message = compressed_signal.tobytes().decode('utf-8', errors='ignore')

        metadata = {
            'type': 'lossy_fft',
            'original_length': original_length,
            'keep_ratio': keep_ratio
        }
        return compressed_message, metadata

    @staticmethod
    def decompress_message(message: str, metadata: dict):
        """
        For lossy compression, we just return the received 'blurry' message.
        Metadata is only informative here — true recovery is impossible.
        """
        return message  # no exact reconstruction possible

class CommunicationSystem(SecureCommunicationSystem):
    def send_lossy_message(self, sender_id: str, receiver_id: str, message_body: str, keep_ratio: float):
        if sender_id not in self.people or receiver_id not in self.people:
            print("Error: sender or receiver not found")
            return False
        
        compressed, metadata = LossyCompression.compress_message(message_body, keep_ratio)
        
        msg_obj = Message(sender_id, receiver_id, compressed, metadata)
        self.messages.append(msg_obj)
        print(f"Lossy message sent from {sender_id} to {receiver_id} with keep_ratio={keep_ratio}")
        return True

    def receive_lossy_message(self, receiver_id: str, message_index: int):
        if message_index >= len(self.messages):
            print(f"Error: Message index {message_index} out of range")
            return None
        
        msg = self.messages[message_index]
        if msg.receiver_id != receiver_id:
            print(f"Error: Message not for {receiver_id}")
            return None
        if msg.metadata.get('type') != 'lossy_fft':
            print("Error: Not a lossy FFT message")
            return None
        
        blurry_text = LossyCompression.decompress_message(msg.message_body, msg.metadata)
        print(f"Lossy message for {receiver_id}: {blurry_text} (original length: {msg.metadata['original_length']})")
        return blurry_text

# Example usage
if __name__ == "__main__":
    ecs = CommunicationSystem()
    ecs.add_person("alice", "Alice")
    ecs.add_person("bob", "Bob")

    ecs.send_lossy_message("alice", "bob", "This is a very detailed secret message!", keep_ratio=0.3)
    bob_msgs = ecs.list_messages_for_person("bob")
    for m in bob_msgs:
        ecs.receive_lossy_message("bob", m['index'])
