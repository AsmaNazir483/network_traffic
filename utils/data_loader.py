import pandas as pd

def load_csv_data(filepath, column_names):
    df = pd.read_csv(filepath, names=column_names)
    return df

def clean_data(df):
    df = df.dropna()
    df = df.drop_duplicates()
    return df