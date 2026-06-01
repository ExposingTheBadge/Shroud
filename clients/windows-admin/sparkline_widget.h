// Tiny sparkline widget — no QtCharts dependency, just QPainter.
// Pass a series of (double) samples and a target color; paints a
// proportional line with optional area-fill underneath. The widget
// auto-rescales to its own height, so multiple sparklines on the same
// row can show series with different magnitudes side-by-side.
#ifndef SHROUD_ADMIN_SPARKLINE_WIDGET_H
#define SHROUD_ADMIN_SPARKLINE_WIDGET_H

#include <QWidget>
#include <QVector>
#include <QColor>

class SparklineWidget : public QWidget {
    Q_OBJECT
public:
    explicit SparklineWidget(QWidget *parent = nullptr);
    void setSeries(const QVector<double> &samples);
    void setLineColor(const QColor &c)  { m_line = c;  update(); }
    void setFillColor(const QColor &c)  { m_fill = c;  update(); }
    QSize sizeHint() const override { return QSize(180, 40); }
    QSize minimumSizeHint() const override { return QSize(60, 24); }
protected:
    void paintEvent(QPaintEvent *) override;
private:
    QVector<double> m_series;
    QColor m_line{0xff, 0xb7, 0x4d};
    QColor m_fill{0xff, 0xb7, 0x4d, 64};
};

#endif
