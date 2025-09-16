import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'Apple TV': [9, 6, 11, 1],
    'Fire TV': [6, 6, 12, 4],
    'Roku TV': [6, 6, 66, 6],
    'Wink hub2': [8, 6, 67, 1],
    'Echoplus': [6, 6, 67, 4],
    'Samsung TV': [8, 6, 56, 7],
    'Thermostat': [2, 6, 13, 0],
    'Echo Dot': [8, 6, 52, 1],
    'Amcrest Camera': [6, 6, 46, 1],
    'D-Link': [12, 0, 0, 12],
    'LG TV': [6, 6, 67, 12],
    'Wemo Plug': [0, 0, 12, 1],
    'Allure Speaker': [13, 6, 46, 1],
}
index = ['secure', 'recommen', 'weak', 'insecure']
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
plt.savefig('./figures/heatmap_ciphersuite.png', dpi=300,  bbox_inches='tight')
plt.show()