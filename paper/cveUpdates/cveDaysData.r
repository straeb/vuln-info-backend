
# Data input form cveUpdateDaysTest.go
input = c(131.8, 103, 103, 6.9, 131.8, 10, 75, 131.8, 40.9, 6.1, 69, 141.5, 95.9, 0, 10.3, 81.8, 27.4, 251.9, 7, 10.3, 132.4, 132.4, 7.7, 6.3, 10.8, 7.1, 48.5, 66.1, 3.7, 66.1, 6.8, 167.1, 155.3, 151, 151, 151, 132, 5.3, 5.2, 5.2, 89.7, 128.5, 115.2, 85.3, 53.2, 184.9, 116.3, 48.8, 84.1, 205.8, 215.5, 168.5, 6, 175.1, 0, 0, 6.8, 9.7, 7.2, 108, 65.8, 7.1, 73.7, 92, 12.9, 5.1, 6.1, 76.1, 117.7, 102.6, 0, 6.1, 93.2)
ordered = order(input)
DF = data.frame(Diff = input[ordered])

# Set terziles
vTert = quantile(DF$Diff, c(0:3/3))

# Label
DF$tert = with(DF, cut(Diff, vTert, include.lowest = T, labels = c("1/3", "2/3", "3/3")))
vTert
DF

# plot
boxplot(Diff ~ tert, data = DF, width = NULL, horizontal = TRUE, ylab = "Intervalle", xlab = "Differenz in Tagen")
