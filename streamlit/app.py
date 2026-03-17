import streamlit as st
import pandas as pd
import numpy as np

st.title("kaasa ho aap sab?")

dataf=pd.DataFrame({
    "name":["manav","kartik","rohan","sahil"],
    "age":[21,22,20,23]})

st.write("yeh mera pehla streamlit app hai")

st.dataframe(dataf)

#line chart
chad=pd.DataFrame(
    np.random.randn(20,3),columns=["a","b","c"]
)

st.bar_chart(chad)