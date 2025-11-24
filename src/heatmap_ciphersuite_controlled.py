import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'tapo cam': [3193, 1216, 7702, 1172],
    'eufy cam': [2562, 1054, 1186, 15],
    'xiaomi am': [235, 155, 1344, 20],
    'd-link cam': [802, 294, 426, 1],
    'sony tv': [15, 11, 46, 1],


}
index = ['secure', 'recommen', 'weak', 'insecure']
df = pd.DataFrame(data, index=index)

import numpy as np

# Create a custom annotation matrix: show value if > 0, else show empty string
annot = df.map(lambda x: f"{x}" if x != 0 else "")

# Plot with custom annotations
plt.figure(figsize=(7, 4))
sns.heatmap(df, annot=annot, cmap= 'crest', fmt='')
#plt.xlabel('IoT Device')
#plt.ylabel('Detected Keyword')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.tight_layout(pad=.01)
# Save the figure if needed
plt.savefig('./figures/heatmap_ciphersuite_controlled.png', dpi=300,  bbox_inches='tight')
plt.show()