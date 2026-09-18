import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
import os

# Seed for reproducibility
SEED = 1337
np.random.seed(SEED)
torch.manual_seed(SEED)


# Define a simple Neural Network
class SimpleNet(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(SimpleNet, self).__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(hidden_size, output_size)
        # Add a larger layer potentially suitable for steganography later
        self.large_layer = nn.Linear(hidden_size, hidden_size * 5)

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        # Note: large_layer is defined but not used in forward pass for simplicity
        # In a real model, all layers would typically be used.
        return x


# Model parameters
input_dim = 10
hidden_dim = 64  # Increased hidden size for larger layers
output_dim = 1
target_model = SimpleNet(input_dim, hidden_dim, output_dim)

print("SimpleNet model structure:")
print(target_model)
print("\nModel parameters (state_dict keys and initial values):")
for name, param in target_model.state_dict().items():
    print(f"  {name}: shape={param.shape}, numel={param.numel()}, dtype={param.dtype}")
    if param.numel() > 0:
        print(f"    Initial values (first 3): {param.flatten()[:3].tolist()}")

# Generate dummy data
num_samples = 100
X_train = torch.randn(num_samples, input_dim)
true_weights = torch.randn(input_dim, output_dim)
y_train = X_train @ true_weights + torch.randn(num_samples, output_dim) * 0.5

# Prepare DataLoader
dataset = TensorDataset(X_train, y_train)
dataloader = DataLoader(dataset, batch_size=16)

# Loss and optimizer
criterion = nn.MSELoss()
optimizer = optim.Adam(target_model.parameters(), lr=0.01)

# Simple training loop
num_epochs = 5 # Minimal training
print(f"\n'Training' the model for {num_epochs} epochs...")
target_model.train() # Set model to training mode
for epoch in range(num_epochs):
    epoch_loss = 0.0
    for inputs, targets in dataloader:
        optimizer.zero_grad()
        outputs = target_model(inputs)
        loss = criterion(outputs, targets)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()
    print(f"  Epoch [{epoch+1}/{num_epochs}], Loss: {epoch_loss/len(dataloader):.4f}")

print("Training complete.")

legitimate_state_dict_file = "target_model.pth"

try:
    # Save the model's state dictionary. torch.save uses pickle internally.
    torch.save(target_model.state_dict(), legitimate_state_dict_file)
    print(f"\nLegitimate model state_dict saved to '{legitimate_state_dict_file}'.")
except Exception as e:
    print(f"\nError saving legitimate state_dict: {e}")
