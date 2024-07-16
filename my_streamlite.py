#!/usr/bin/env python
# coding: utf-8

import streamlit as st
import pandas as pd 
import numpy as np 
from pymongo import MongoClient

option = st.sidebar.selectbox(
    'Silakan pilih:',
    ('Home', 'Dataframe')
)

if option == 'Home' or option == '':
    st.write("""# Halaman Utama""")  # menampilkan halaman utama
elif option == 'Dataframe':
    st.write("""## Dataframe""")  # menampilkan judul halaman dataframe

    # Koneksi ke MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    db = client['helmet']
    collection = db['counting']
    
    # Mengambil data dari MongoDB dan membentuk DataFrame
    cursor = collection.find({})
    df = pd.DataFrame(list(cursor))

    # Menampilkan DataFrame
    st.write(df)
    

    st.write("""## Hasil Visualisasi""")  # Menampilkan judul halaman 

    # Menghitung jumlah data berlabel 'Helmet' dan 'No Helmet' berdasarkan lokasi
    data_per_location = df.groupby(['location', 'label']).size().unstack(fill_value=0)

    # Menyiapkan data untuk chart dan tabel
    table = data_per_location

    # Menampilkan data dalam bentuk chart
    st.bar_chart(table)

    # Menampilkan data dalam bentuk tabel
    st.write(table)
