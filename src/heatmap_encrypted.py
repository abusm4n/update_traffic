import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'Apple TV': [0, 11, 0, 0],
    'Roku TV': [0, 4, 0, 0],
    'Wink hub2': [0, 6, 0, 0],
    'Echoplus': [0, 5, 5, 1],
    'Samsung TV': [0, 0, 5, 3],
    'Invoke': [0, 10, 0, 0],
    'Unctrl': [0, 21, 14, 0],
    'Thermostat': [0, 6, 0, 0],
    'Fire TV': [0, 4, 4, 0],
    'Echo dot': [0, 4, 4, 0],
}
index = ['firmware', 'update', 'software', 'download']
df = pd.DataFrame(data, index=index)

import numpy as np

# Create a custom annotation matrix: show value if > 0, else show empty string
annot = df.map(lambda x: f"{x}" if x != 0 else "")

# Plot with custom annotations
plt.figure(figsize=(7, 4))
sns.heatmap(df, annot=annot, cmap='Blues', fmt='')
#plt.xlabel('IoT Device')
#plt.ylabel('Detected Keyword')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.tight_layout(pad=.01)
# Save the figure if needed
plt.savefig('./figures/heatmap_encrypted.png', dpi=300,  bbox_inches='tight')
plt.show()