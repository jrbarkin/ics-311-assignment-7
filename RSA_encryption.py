import random
import math
from typing import Dict, Tuple, Optional

class RSAKeyPair:
    def __init__(self, public_key: Tuple[int, int], private_key: Tuple[int, int]):
        self.public_key = public_key  # (e, n)
        self.private_key = private_key  # (d, n)

class Person:
    def __init__(self, node_id: str, name: str):
        self.node_id = node_id
        self.name = name
        self.rsa_keys: Optional[RSAKeyPair] = None
        self.connections = set()  # Set of connected person IDs
    
    def add_connection(self, person_id: str):
        self.connections.add(person_id)
    
    def generate_rsa_keys(self, key_size: int = 512):
        self.rsa_keys = RSAEncryption.generate_key_pair(key_size)

class Message:
    def __init__(self, sender_id: str, receiver_id: str, message_body: str, metadata: Dict):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_body = message_body
        self.metadata = metadata

class RSAEncryption:
    @staticmethod
    def is_prime(n: int, k: int = 5) -> bool:
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
        
        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    @staticmethod
    def generate_prime(bits: int) -> int:
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Set MSB and LSB
            if RSAEncryption.is_prime(candidate):
                return candidate
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSAEncryption.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        gcd, x, _ = RSAEncryption.extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
    
    @staticmethod
    def generate_key_pair(key_size: int = 512) -> RSAKeyPair:
        p = RSAEncryption.generate_prime(key_size // 2)
        q = RSAEncryption.generate_prime(key_size // 2)
        while q == p:
            q = RSAEncryption.generate_prime(key_size // 2)
        
        # Calculate n and phi(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # Choose e (commonly 65537)
        e = 65537
        while math.gcd(e, phi_n) != 1:
            e += 2
        
        # Calculate d (private exponent)
        d = RSAEncryption.mod_inverse(e, phi_n)
        
        public_key = (e, n)
        private_key = (d, n)
        
        return RSAKeyPair(public_key, private_key)
    
    @staticmethod
    def string_to_int_blocks(message: str, block_size: int) -> list:
        """Convert string to list of integers for encryption."""
        message_bytes = message.encode('utf-8')
        blocks = []
        
        for i in range(0, len(message_bytes), block_size):
            block = message_bytes[i:i + block_size]
            # Convert bytes to integer
            block_int = int.from_bytes(block, byteorder='big')
            blocks.append(block_int)
        
        return blocks
    
    @staticmethod
    def int_blocks_to_string(blocks: list, block_size: int) -> str:
        message_bytes = b''
        
        for block_int in blocks:
            # Convert integer back to bytes
            byte_length = (block_int.bit_length() + 7) // 8
            if byte_length == 0:
                byte_length = 1
            block_bytes = block_int.to_bytes(byte_length, byteorder='big')
            message_bytes += block_bytes
        
        return message_bytes.decode('utf-8')
    
    @staticmethod
    def encrypt_message(message: str, public_key: Tuple[int, int]) -> Tuple[list, Dict]:
        e, n = public_key
        
        max_block_size = (n.bit_length() - 1) // 8
        if max_block_size < 1:
            max_block_size = 1
        
        blocks = RSAEncryption.string_to_int_blocks(message, max_block_size)
        
        encrypted_blocks = []
        for block in blocks:
            if block >= n:
                raise ValueError(f"Block too large for key size: {block} >= {n}")
            encrypted_block = pow(block, e, n)
            encrypted_blocks.append(encrypted_block)
        
        metadata = {
            'type': 'rsa_encrypted',
            'block_size': max_block_size,
            'num_blocks': len(encrypted_blocks),
            'public_key_n': n,
            'public_key_e': e
        }
        
        return encrypted_blocks, metadata
    
    @staticmethod
    def decrypt_message(encrypted_blocks: list, private_key: Tuple[int, int], metadata: Dict) -> str:
        d, n = private_key
        block_size = metadata['block_size']
        
        # Decrypt each block
        decrypted_blocks = []
        for encrypted_block in encrypted_blocks:
            decrypted_block = pow(encrypted_block, d, n)
            decrypted_blocks.append(decrypted_block)
        
        # Convert blocks back to string
        return RSAEncryption.int_blocks_to_string(decrypted_blocks, block_size)

class SecureCommunicationSystem:    
    def __init__(self):
        self.people: Dict[str, Person] = {}
        self.messages: list = []
    
    def add_person(self, person_id: str, name: str) -> Person:
        person = Person(person_id, name)
        person.generate_rsa_keys()
        self.people[person_id] = person
        return person
    
    def add_connection(self, person1_id: str, person2_id: str):
        if person1_id in self.people and person2_id in self.people:
            self.people[person1_id].add_connection(person2_id)
            self.people[person2_id].add_connection(person1_id)
    
    def get_public_key(self, person_id: str) -> Optional[Tuple[int, int]]:
        if person_id in self.people and self.people[person_id].rsa_keys:
            return self.people[person_id].rsa_keys.public_key
        return None
    
    def send_encrypted_message(self, sender_id: str, receiver_id: str, message_body: str) -> bool:

        if sender_id not in self.people or receiver_id not in self.people:
            print(f"Error: Sender or receiver not found")
            return False
        
        receiver_public_key = self.get_public_key(receiver_id)
        if not receiver_public_key:
            print(f"Error: Could not get public key for receiver {receiver_id}")
            return False
        
        try:
            # Encrypt the message
            encrypted_blocks, metadata = RSAEncryption.encrypt_message(message_body, receiver_public_key)
            
            # Create message object
            message = Message(
                sender_id=sender_id,
                receiver_id=receiver_id,
                message_body=encrypted_blocks,  # Store encrypted blocks
                metadata=metadata
            )
            
            # Store message
            self.messages.append(message)
            print(f"Encrypted message sent from {sender_id} to {receiver_id}")
            return True
            
        except Exception as e:
            print(f"Error encrypting message: {e}")
            return False
    
    def receive_encrypted_message(self, receiver_id: str, message_index: int) -> Optional[str]:
        if message_index >= len(self.messages):
            print(f"Error: Message index {message_index} not found")
            return None
        
        message = self.messages[message_index]
        
        if message.receiver_id != receiver_id:
            print(f"Error: Message not intended for {receiver_id}")
            return None
        
        if message.metadata.get('type') != 'rsa_encrypted':
            print(f"Error: Message is not RSA encrypted")
            return None
        
        receiver = self.people.get(receiver_id)
        if not receiver or not receiver.rsa_keys:
            print(f"Error: Could not get private key for {receiver_id}")
            return None
        
        try:
            # Decrypt the message
            decrypted_message = RSAEncryption.decrypt_message(
                message.message_body,
                receiver.rsa_keys.private_key,
                message.metadata
            )
            
            print(f"Message decrypted for {receiver_id}")
            return decrypted_message
            
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return None
    
    def list_messages_for_person(self, person_id: str) -> list:
        person_messages = []
        for i, message in enumerate(self.messages):
            if message.receiver_id == person_id:
                person_messages.append({
                    'index': i,
                    'sender': message.sender_id,
                    'type': message.metadata.get('type', 'unknown')
                })
        return person_messages

# Example usage and testing
if __name__ == "__main__":
    # create communication system
    comm_system = SecureCommunicationSystem()
    
    # add people to the system
    alice = comm_system.add_person("alice", "alice")
    bob = comm_system.add_person("bob", "bob")
    charlie = comm_system.add_person("charlie", "charlie")
    
    # add connections
    comm_system.add_connection("alice", "bob")
    comm_system.add_connection("bob", "charlie")
    
    # send encrypted messages
    print("encrypted messaging:")

    # alice sends encrypted message to bob
    success = comm_system.send_encrypted_message(
        "alice", "bob", 
        "hello bob! This is a secret message from alice."
    )
    
    # bob sends encrypted message to charlie
    success = comm_system.send_encrypted_message(
        "bob", "charlie",
        "hi charlie, this is confidential"
    )

    # alice sends another message to charlie
    success = comm_system.send_encrypted_message(
        "alice", "charlie",
        "charlie, this is alice."
    )

    # bob receives his messages
    bob_messages = comm_system.list_messages_for_person("bob")
    print(f"bob has {len(bob_messages)} messages:")
    for msg_info in bob_messages:
        decrypted = comm_system.receive_encrypted_message("bob", msg_info['index'])
        print(f"  From {msg_info['sender']}: {decrypted}")

    # charlie receives his messages
    charlie_messages = comm_system.list_messages_for_person("charlie")
    print(f"\ncharlie has {len(charlie_messages)} messages:")
    for msg_info in charlie_messages:
        decrypted = comm_system.receive_encrypted_message("charlie", msg_info['index'])
        print(f"  From {msg_info['sender']}: {decrypted}")
    
    # try to have alice read bob's message (should fail)
    if bob_messages:
        print("Attempting to have alice decrypt bob's message...")
        result = comm_system.receive_encrypted_message("alice", bob_messages[0]['index'])
        if result is None:
            print("alice cannot read bob's messages")
    
    print(f"alice's public key: {alice.rsa_keys.public_key}")
    print(f"bob's public key: {bob.rsa_keys.public_key}")
    print(f"charlie's public key: {charlie.rsa_keys.public_key}")
    print("\nthus, private keys are kept secret by each person")