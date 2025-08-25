import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'Apple TV': [0, 1, 1, 1],
    'Roku TV': [0, 0, 76, 0],
    'Amcrest Camera': [13, 0, 0, 0],
    'D-Link Sensor': [6, 0, 0, 6],
    'LG TV': [10, 12, 0, 0],
    'WeMo Plug': [602, 602, 0, 1],
    'Samsung TV': [8, 228, 6, 0],
    'Philips Hub': [0, 509, 0, 0],
    'Allure Speaker': [0, 0, 6, 0],
    'Uncontrol': [96, 217, 0, 14],
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
plt.savefig('./figures/heatmap_unencrypted.png', dpi=300,  bbox_inches='tight')
plt.show()